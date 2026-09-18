//! CSR builder for ANS agent registration.
//!
//! Generates correctly-configured Certificate Signing Requests for both ANS
//! certificate types. Handles key generation and sets all required extensions
//! so callers cannot accidentally submit an invalid CSR.
//!
//! ## Key algorithm
//!
//! This helper currently generates **RSA-2048** keys for both the TLS server
//! certificate and the mTLS identity certificate — the only algorithm the ANS
//! PKI issues for. ECDSA (P-256) generation for ANS-6 Method B is planned as a
//! follow-up; until then a P-256 request must be built by hand.
//!
//! ## Requirements enforced automatically
//!
//! | Certificate | EKU          | Key Usage                             | SANs         |
//! |-------------|--------------|---------------------------------------|--------------|
//! | Server      | `ServerAuth` | `DigitalSignature`, `KeyEncipherment` | DNS          |
//! | Identity    | `ClientAuth` | `DigitalSignature`                    | DNS + ANS URI|
//!
//! The versioned ANS URI SAN belongs to the private Identity Certificate
//! (ANS-2 §3); the public Server Certificate is bound by DNS name alone.
//! Public CAs reject requests carrying a URI SAN — Boulder's `VerifyCSR` in
//! particular — so a server CSR must not contain one.
//!
//! ## Example
//!
//! ```rust,no_run
//! use ans_client::{AnsCsrBuilder, Fqdn, Version};
//! use secrecy::ExposeSecret;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let host = Fqdn::new("race-ready.ai")?;
//! let version = Version::parse("0.1.2")?;
//!
//! let server = AnsCsrBuilder::server(host.clone(), version.clone()).build()?;
//! // server.csr_pem — submit to ANS registration
//! // server.private_key_pem.expose_secret() — RSA-2048 PKCS#8 PEM, store securely
//!
//! let identity = AnsCsrBuilder::identity(host, version).build()?;
//! # Ok(())
//! # }
//! ```

use ans_types::{AnsName, Fqdn, ParseError, Version};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, SanType,
};
use secrecy::SecretString;
use thiserror::Error;

/// The output of a successful [`AnsCsrBuilder::build`] call.
///
/// The private key is held in a [`SecretString`], so it is redacted from
/// `Debug` output and zeroized on drop. Call `expose_secret()` when you are
/// ready to persist it.
#[derive(Debug, Clone)]
pub struct CsrOutput {
    /// PEM-encoded Certificate Signing Request ready for submission to ANS.
    pub csr_pem: String,
    /// PKCS#8 PEM-encoded RSA-2048 private key. Store this securely — it never
    /// leaves the process on its own.
    pub private_key_pem: SecretString,
}

/// Errors that can occur when building an ANS CSR.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CsrError {
    /// The host and version do not form a parseable ANS name.
    #[error("invalid ANS name: {0}")]
    InvalidName(#[from] ParseError),

    /// A SAN value could not be encoded as an IA5 string.
    #[error("invalid SAN value: {0}")]
    InvalidSan(String),

    /// rcgen failed to generate the key pair or serialize the CSR.
    #[error("CSR serialization failed: {0}")]
    Serialization(#[from] rcgen::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CsrKind {
    Server,
    Identity,
}

/// Builder for ANS-compliant Certificate Signing Requests.
///
/// Use [`AnsCsrBuilder::server`] for the TLS server certificate CSR and
/// [`AnsCsrBuilder::identity`] for the mTLS client identity certificate CSR.
///
/// Both take the validated domain types [`Fqdn`] and [`Version`], so a builder
/// cannot be constructed from a malformed hostname or version string. Parse
/// untrusted input with [`Fqdn::new`] and [`Version::parse`] first.
#[derive(Debug)]
pub struct AnsCsrBuilder {
    host: Fqdn,
    version: Version,
    kind: CsrKind,
}

impl AnsCsrBuilder {
    /// Build a **server** CSR: `ServerAuth` EKU, `DigitalSignature` +
    /// `KeyEncipherment` key usage, DNS SAN only.
    ///
    /// Generates an RSA-2048 key pair when [`build`](Self::build) is called.
    pub fn server(host: Fqdn, version: Version) -> Self {
        Self {
            host,
            version,
            kind: CsrKind::Server,
        }
    }

    /// Build an **identity** CSR: `ClientAuth` EKU, `DigitalSignature` key
    /// usage, DNS SAN plus the versioned `ans://` URI SAN.
    ///
    /// Generates an RSA-2048 key pair when [`build`](Self::build) is called.
    pub fn identity(host: Fqdn, version: Version) -> Self {
        Self {
            host,
            version,
            kind: CsrKind::Identity,
        }
    }

    /// Generate the RSA-2048 key pair and produce the CSR.
    ///
    /// The returned [`CsrOutput`] contains the PEM-encoded CSR and the
    /// corresponding private key. The private key is not transmitted anywhere —
    /// the caller is responsible for storing it securely.
    ///
    /// # Errors
    /// Returns [`CsrError::InvalidName`] if the host and version do not form a
    /// parseable [`AnsName`], and [`CsrError::Serialization`] if key generation
    /// or CSR encoding fails.
    pub fn build(self) -> Result<CsrOutput, CsrError> {
        // Validate the ANS name before spending time on key generation.
        let sans = build_sans(&self.host, &self.version, self.kind)?;

        let key_pair = generate_rsa_key_pair()?;
        let csr_pem = build_csr(&key_pair, &self.host, sans, self.kind)?;

        Ok(CsrOutput {
            csr_pem,
            private_key_pem: SecretString::from(key_pair.serialize_pem()),
        })
    }
}

fn generate_rsa_key_pair() -> Result<KeyPair, CsrError> {
    // RSA-2048 key generation via aws-lc-rs (BoringSSL).  The `ring` crate
    // does not support RSA key generation; the `rsa` pure-Rust crate carries
    // RUSTSEC-2023-0071 (Marvin Attack timing side-channel in decryption).
    KeyPair::generate_for(&PKCS_RSA_SHA256).map_err(CsrError::Serialization)
}

/// Build the SAN list for `kind`.
///
/// Every CSR carries the DNS SAN. Only the identity CSR carries the versioned
/// ANS URI SAN — public CAs reject requests containing URI SANs, and ANS-2 §3
/// assigns that binding to the Identity Certificate.
fn build_sans(host: &Fqdn, version: &Version, kind: CsrKind) -> Result<Vec<SanType>, CsrError> {
    let dns_san = ia5(host.as_str())?;
    let mut sans = vec![SanType::DnsName(dns_san)];

    if kind == CsrKind::Identity {
        // `Version` renders as `v1.2.3` and `Fqdn` is already normalized, so
        // this is the canonical ANS name. Round-trip it to be certain.
        let ans_name: AnsName = format!("ans://{version}.{host}").parse()?;
        sans.push(SanType::URI(ia5(&ans_name.to_string())?));
    }

    Ok(sans)
}

fn ia5(value: &str) -> Result<rcgen::string::Ia5String, CsrError> {
    rcgen::string::Ia5String::try_from(value.to_string())
        .map_err(|e| CsrError::InvalidSan(e.to_string()))
}

fn build_csr(
    key_pair: &KeyPair,
    host: &Fqdn,
    sans: Vec<SanType>,
    kind: CsrKind,
) -> Result<String, CsrError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host.as_str());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = sans;

    match kind {
        CsrKind::Server => {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
        }
        CsrKind::Identity => {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
    }

    let csr = params.serialize_request(key_pair)?;
    Ok(csr.pem()?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn host() -> Fqdn {
        Fqdn::new("example.ai").expect("valid fqdn")
    }

    fn version() -> Version {
        Version::new(1, 0, 0)
    }

    #[test]
    fn server_csr_builds_without_error() {
        let out = AnsCsrBuilder::server(host(), version())
            .build()
            .expect("server CSR should build");
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(out.private_key_pem.expose_secret().contains("PRIVATE KEY"));
    }

    #[test]
    fn identity_csr_builds_without_error() {
        let out = AnsCsrBuilder::identity(host(), version())
            .build()
            .expect("identity CSR should build");
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(out.private_key_pem.expose_secret().contains("PRIVATE KEY"));
    }

    #[test]
    fn server_and_identity_keys_are_independent() {
        let server = AnsCsrBuilder::server(host(), version())
            .build()
            .expect("server CSR");
        let identity = AnsCsrBuilder::identity(host(), version())
            .build()
            .expect("identity CSR");
        assert_ne!(
            server.private_key_pem.expose_secret(),
            identity.private_key_pem.expose_secret(),
            "each call should produce a fresh key pair"
        );
    }

    #[test]
    fn identity_sans_carry_canonical_ans_uri() {
        let sans = build_sans(&host(), &Version::new(1, 2, 3), CsrKind::Identity)
            .expect("sans should build");
        let uris: Vec<String> = sans
            .iter()
            .filter_map(|san| match san {
                SanType::URI(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(uris, vec!["ans://v1.2.3.example.ai".to_string()]);
    }

    #[test]
    fn server_sans_carry_no_uri() {
        let sans = build_sans(&host(), &Version::new(1, 2, 3), CsrKind::Server)
            .expect("sans should build");
        assert!(
            !sans.iter().any(|san| matches!(san, SanType::URI(_))),
            "server CSR must not contain a URI SAN"
        );
    }
}
