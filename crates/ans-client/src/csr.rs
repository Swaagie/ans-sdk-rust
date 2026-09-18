//! CSR builder for ANS agent registration.
//!
//! Generates Certificate Signing Requests for both ANS certificate types,
//! including key generation and every extension the RA requires.
//!
//! ## Key algorithm
//!
//! RSA-2048 is this SDK's default, not a PKI limit — the RA also accepts
//! larger RSA and ECDSA P-256/P-384.
//!
//! ## Requirements enforced automatically
//!
//! | Certificate | Subject CN | EKU          | Key Usage                             | SANs          |
//! |-------------|------------|--------------|---------------------------------------|---------------|
//! | Server      | *omitted*  | `ServerAuth` | `DigitalSignature`, `KeyEncipherment` | DNS           |
//! | Identity    | FQDN       | `ClientAuth` | `DigitalSignature`                    | DNS + ANS URI |
//!
//! The URI SAN is identity-only: public CAs reject a server CSR that carries
//! one, and ANS-2 §3 assigns that binding to the Identity Certificate.
//!
//! ## Subject Common Name
//!
//! The server CSR omits the CN. It is deprecated and optional for public CAs,
//! which read the DNS SAN instead and silently drop a CN over RFC 5280's
//! 64-character `ub-common-name`, so setting it buys nothing and makes the
//! request depend on per-CA handling of an over-length field.
//!
//! The identity CSR keeps it. The ANS private CA copies the CSR subject and
//! adds no DNS SAN, leaving the CN as the identity certificate's only FQDN
//! carrier for mTLS verification, so a host over 64 characters cannot yield a
//! conformant identity certificate.
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

/// A generated CSR and the private key it was signed with.
///
/// The key is redacted from `Debug` and zeroized on drop; call
/// `expose_secret()` to persist it.
#[derive(Debug, Clone)]
pub struct CsrOutput {
    /// PEM-encoded Certificate Signing Request ready for submission to ANS.
    pub csr_pem: String,
    /// PKCS#8 PEM private key, never transmitted by this crate.
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
/// Taking [`Fqdn`] and [`Version`] rather than strings makes a malformed host
/// or version unrepresentable; parse untrusted input with [`Fqdn::new`] and
/// [`Version::parse`] first.
#[derive(Debug)]
pub struct AnsCsrBuilder {
    host: Fqdn,
    version: Version,
    kind: CsrKind,
}

impl AnsCsrBuilder {
    /// Build a **server** CSR: `ServerAuth` EKU, `DigitalSignature` +
    /// `KeyEncipherment` key usage, DNS SAN only, no subject CN.
    pub fn server(host: Fqdn, version: Version) -> Self {
        Self {
            host,
            version,
            kind: CsrKind::Server,
        }
    }

    /// Build an **identity** CSR: `ClientAuth` EKU, `DigitalSignature` key
    /// usage, DNS SAN plus the versioned `ans://` URI SAN, host as subject CN.
    pub fn identity(host: Fqdn, version: Version) -> Self {
        Self {
            host,
            version,
            kind: CsrKind::Identity,
        }
    }

    /// Generate a fresh RSA-2048 key pair and produce the CSR.
    ///
    /// # Errors
    /// [`CsrError::InvalidName`] if the host and version do not form a
    /// parseable [`AnsName`], [`CsrError::Serialization`] if key generation or
    /// CSR encoding fails.
    pub fn build(self) -> Result<CsrOutput, CsrError> {
        // Validated before key generation, which is the expensive step.
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
    // aws-lc-rs, because `ring` cannot generate RSA keys at all and the `rsa`
    // crate carries RUSTSEC-2023-0071 (Marvin timing side-channel).
    KeyPair::generate_for(&PKCS_RSA_SHA256).map_err(CsrError::Serialization)
}

fn build_sans(host: &Fqdn, version: &Version, kind: CsrKind) -> Result<Vec<SanType>, CsrError> {
    let dns_san = ia5(host.as_str())?;
    let mut sans = vec![SanType::DnsName(dns_san)];

    if kind == CsrKind::Identity {
        // Round-tripped rather than pushed as a string so a malformed name
        // fails here instead of at the RA.
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
    if kind == CsrKind::Identity {
        // Identity certs get no DNS SAN from the CA, so the CN is their only
        // FQDN carrier; on the server side it is deprecated and unread.
        dn.push(DnType::CommonName, host.as_str());
    }

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
