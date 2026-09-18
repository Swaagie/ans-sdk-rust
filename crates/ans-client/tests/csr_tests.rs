#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_test_module
)]
//! Tests for [`AnsCsrBuilder`].
//!
//! Each test parses the generated CSR with `x509-parser` to verify that
//! Subject CN, SANs, Extended Key Usage, and Key Usage extensions are exactly
//! what the ANS PKI requires.

use ans_client::csr::AnsCsrBuilder;
use ans_client::{AnsName, Fqdn, Version};
use rstest::rstest;
use secrecy::ExposeSecret;
use x509_parser::{pem::parse_x509_pem, prelude::*, public_key::PublicKey};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fqdn(host: &str) -> Fqdn {
    Fqdn::new(host).expect("test host must be a valid FQDN")
}

fn version(v: &str) -> Version {
    Version::parse(v).expect("test version must be valid")
}

fn server_csr(host: &str, v: &str) -> ans_client::CsrOutput {
    AnsCsrBuilder::server(fqdn(host), version(v))
        .build()
        .expect("server CSR should build")
}

fn identity_csr(host: &str, v: &str) -> ans_client::CsrOutput {
    AnsCsrBuilder::identity(fqdn(host), version(v))
        .build()
        .expect("identity CSR should build")
}

/// Decode a PEM-encoded CSR to its raw DER bytes.
fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, pem_obj) = parse_x509_pem(pem.as_bytes()).expect("PEM decode failed");
    pem_obj.contents
}

/// Run `f` over every requested extension of the CSR, returning the first
/// `Some` result.
fn find_extension<T>(csr_pem: &str, f: impl FnMut(&ParsedExtension<'_>) -> Option<T>) -> Option<T> {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.requested_extensions()
        .and_then(|mut exts| exts.find_map(f))
}

/// Every `GeneralName` in the CSR's Subject Alternative Name extension.
fn subject_alt_names(csr_pem: &str) -> Vec<String> {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::SubjectAlternativeName(san) => Some(
            san.general_names
                .iter()
                .map(|n| match n {
                    GeneralName::DNSName(d) => format!("DNS:{d}"),
                    GeneralName::URI(u) => format!("URI:{u}"),
                    other => format!("OTHER:{other:?}"),
                })
                .collect(),
        ),
        _ => None,
    })
    .expect("CSR must carry a SubjectAlternativeName extension")
}

fn key_usage(csr_pem: &str) -> KeyUsage {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::KeyUsage(ku) => Some(*ku),
        _ => None,
    })
    .expect("KeyUsage extension must be present")
}

/// Returns `(server_auth, client_auth)`.
fn eku(csr_pem: &str) -> (bool, bool) {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::ExtendedKeyUsage(eku) => Some((eku.server_auth, eku.client_auth)),
        _ => None,
    })
    .expect("ExtendedKeyUsage extension must be present")
}

fn common_name(csr_pem: &str) -> String {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.certification_request_info
        .subject
        .iter_common_name()
        .next()
        .expect("subject must contain a CN")
        .as_str()
        .expect("CN must be a printable string")
        .to_string()
}

fn rsa_key_size(csr_pem: &str) -> usize {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    let Ok(PublicKey::RSA(rsa_pk)) = csr.certification_request_info.subject_pki.parsed() else {
        panic!("CSR must embed an RSA public key");
    };
    rsa_pk.key_size()
}

// ── Subject CN ────────────────────────────────────────────────────────────────

#[test]
fn server_csr_cn_equals_hostname() {
    let out = server_csr("agent.example.com", "1.2.3");
    assert_eq!(common_name(&out.csr_pem), "agent.example.com");
}

#[test]
fn identity_csr_cn_equals_hostname() {
    let out = identity_csr("id.example.ai", "0.9.1");
    assert_eq!(common_name(&out.csr_pem), "id.example.ai");
}

// ── SANs ──────────────────────────────────────────────────────────────────────

#[test]
fn server_csr_san_contains_dns_hostname() {
    let out = server_csr("svc.example.com", "2.0.0");
    assert!(
        subject_alt_names(&out.csr_pem).contains(&"DNS:svc.example.com".to_string()),
        "SAN must contain DNS:svc.example.com"
    );
}

#[test]
fn identity_csr_san_contains_dns_hostname() {
    let out = identity_csr("id.example.ai", "1.0.0");
    assert!(
        subject_alt_names(&out.csr_pem).contains(&"DNS:id.example.ai".to_string()),
        "SAN must contain DNS:id.example.ai"
    );
}

/// The public Server Certificate is bound by DNS name only (ANS-2 §3). A URI
/// SAN in the request is also fatal at public CAs — Boulder's `VerifyCSR`
/// rejects it outright, and the ANS ACME issuer forwards the CSR unchanged.
#[rstest]
#[case("example.ai", "1.0.0")]
#[case("my-agent.example.com", "0.1.2")]
#[case("race-ready.ai", "10.20.30")]
fn server_csr_has_no_uri_san(#[case] host: &str, #[case] v: &str) {
    let out = server_csr(host, v);
    let sans = subject_alt_names(&out.csr_pem);

    assert_eq!(
        sans,
        vec![format!("DNS:{host}")],
        "server CSR must carry the DNS SAN and nothing else"
    );
    assert!(
        !sans.iter().any(|s| s.starts_with("URI:")),
        "server CSR must not carry a URI SAN, got {sans:?}"
    );
}

/// The URI SAN must be `ans://v{version}.{host}` so that the ANS verifier can
/// extract the version and FQDN from the mTLS identity certificate.
#[rstest]
#[case("example.ai", "1.0.0", "ans://v1.0.0.example.ai")]
#[case("id.svc.com", "2.3.4", "ans://v2.3.4.id.svc.com")]
#[case("my-agent.example.com", "0.1.2", "ans://v0.1.2.my-agent.example.com")]
#[case("race-ready.ai", "10.20.30", "ans://v10.20.30.race-ready.ai")]
fn identity_csr_san_uri_is_ans_format(
    #[case] host: &str,
    #[case] v: &str,
    #[case] expected_uri: &str,
) {
    let out = identity_csr(host, v);
    let sans = subject_alt_names(&out.csr_pem);

    assert_eq!(
        sans,
        vec![format!("DNS:{host}"), format!("URI:{expected_uri}")],
        "identity CSR must carry the DNS SAN followed by the ANS URI SAN"
    );
    AnsName::parse(expected_uri).expect("generated URI SAN must round-trip through AnsName");
}

/// `Version` renders with its own `v` prefix (`v1.2.3`). The builder must not
/// add a second one — `ans://vv1.2.3.…` is rejected by `AnsName::parse`.
#[test]
fn identity_csr_uri_san_does_not_double_prefix_version() {
    let out = AnsCsrBuilder::identity(fqdn("agent.example.com"), Version::new(1, 2, 3))
        .build()
        .expect("identity CSR should build");

    let uri = subject_alt_names(&out.csr_pem)
        .into_iter()
        .find_map(|s| s.strip_prefix("URI:").map(str::to_string))
        .expect("identity CSR must carry a URI SAN");

    assert_eq!(uri, "ans://v1.2.3.agent.example.com");
    assert!(!uri.contains("vv"), "version prefix must not be doubled");

    let parsed = AnsName::parse(&uri).expect("URI SAN must parse as an ANS name");
    assert_eq!(parsed.version(), &Version::new(1, 2, 3));
    assert_eq!(parsed.fqdn().as_str(), "agent.example.com");
}

/// `Version::parse` accepts both `1.2.3` and `v1.2.3`; either spelling must
/// produce the same canonical URI SAN.
#[test]
fn identity_csr_uri_san_is_independent_of_version_spelling() {
    let bare = identity_csr("agent.example.com", "1.2.3");
    let prefixed = identity_csr("agent.example.com", "v1.2.3");

    assert_eq!(
        subject_alt_names(&bare.csr_pem),
        subject_alt_names(&prefixed.csr_pem)
    );
}

// ── Input validation ──────────────────────────────────────────────────────────

/// The builder takes validated `Fqdn` / `Version` values, so malformed input is
/// rejected before a key pair is ever generated.
#[rstest]
#[case::empty("")]
#[case::space("bad host")]
#[case::empty_label("a..b")]
#[case::label_too_long(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
)]
#[case::underscore("bad_host.example.com")]
#[case::leading_hyphen("-bad.example.com")]
fn invalid_hosts_are_rejected(#[case] host: &str) {
    assert!(
        Fqdn::new(host).is_err(),
        "{host:?} must not parse as an FQDN"
    );
}

#[rstest]
#[case::empty("")]
#[case::two_parts("1.2")]
#[case::four_parts("1.2.3.4")]
#[case::prerelease("1.2.3-rc1")]
#[case::build_metadata("1.2.3+build.5")]
#[case::non_numeric("a.b.c")]
fn invalid_versions_are_rejected(#[case] v: &str) {
    assert!(Version::parse(v).is_err(), "{v:?} must not parse");
}

/// `Fqdn` normalizes case, so the CN, DNS SAN and URI SAN all use the
/// lowercase form regardless of how the caller spelled the host.
#[test]
fn host_is_normalized_to_lowercase() {
    let out = identity_csr("Agent.Example.COM", "1.0.0");

    assert_eq!(common_name(&out.csr_pem), "agent.example.com");
    assert_eq!(
        subject_alt_names(&out.csr_pem),
        vec![
            "DNS:agent.example.com".to_string(),
            "URI:ans://v1.0.0.agent.example.com".to_string(),
        ]
    );
}

// ── Extended Key Usage ────────────────────────────────────────────────────────

/// Server CSRs must request `id-kp-serverAuth` (OID 1.3.6.1.5.5.7.3.1).
/// Submitting a CSR with `clientAuth` would result in a 422 from the ANS API.
#[test]
fn server_csr_has_server_auth_eku_only() {
    let out = server_csr("agent.example.com", "1.0.0");
    let (server_auth, client_auth) = eku(&out.csr_pem);

    assert!(server_auth, "server CSR must request ServerAuth EKU");
    assert!(!client_auth, "server CSR must not request ClientAuth EKU");
}

#[test]
fn identity_csr_has_client_auth_eku_only() {
    let out = identity_csr("agent.example.com", "1.0.0");
    let (server_auth, client_auth) = eku(&out.csr_pem);

    assert!(!server_auth, "identity CSR must not request ServerAuth EKU");
    assert!(client_auth, "identity CSR must request ClientAuth EKU");
}

// ── Key Usage ─────────────────────────────────────────────────────────────────

/// Server certificates are used for TLS and need both `digitalSignature` (for
/// TLS 1.3 handshakes) and `keyEncipherment` (for RSA key exchange in TLS 1.2).
#[test]
fn server_csr_key_usage_digital_signature_and_key_encipherment() {
    let out = server_csr("agent.example.com", "1.0.0");
    let ku = key_usage(&out.csr_pem);

    assert!(
        ku.digital_signature(),
        "server CSR must request DigitalSignature"
    );
    assert!(
        ku.key_encipherment(),
        "server CSR must request KeyEncipherment"
    );
    // Sanity: bits that must NOT be set
    assert!(
        !ku.key_agreement(),
        "server CSR must not request KeyAgreement"
    );
    assert!(
        !ku.data_encipherment(),
        "server CSR must not request DataEncipherment"
    );
}

/// Identity (mTLS client) certificates only need `digitalSignature`; they are
/// never used for key exchange, so `keyEncipherment` must be absent.
#[test]
fn identity_csr_key_usage_digital_signature_only() {
    let out = identity_csr("agent.example.com", "1.0.0");
    let ku = key_usage(&out.csr_pem);

    assert!(
        ku.digital_signature(),
        "identity CSR must request DigitalSignature"
    );
    assert!(
        !ku.key_encipherment(),
        "identity CSR must not request KeyEncipherment"
    );
    assert!(
        !ku.key_agreement(),
        "identity CSR must not request KeyAgreement"
    );
}

// ── RSA-2048 key ──────────────────────────────────────────────────────────────

/// ANS PKI only accepts RSA-2048 keys; ECDSA keys lead to indefinite
/// `PENDING_CERTS` stalls with no error indication.
///
/// The key size is checked via the public key embedded in the CSR itself
/// (`SubjectPublicKeyInfo`), so no separate key-parsing dependency is needed.
#[test]
fn server_csr_embeds_rsa_2048_public_key() {
    assert_eq!(
        rsa_key_size(&server_csr("agent.example.com", "1.0.0").csr_pem),
        2048
    );
}

#[test]
fn identity_csr_embeds_rsa_2048_public_key() {
    assert_eq!(
        rsa_key_size(&identity_csr("agent.example.com", "1.0.0").csr_pem),
        2048
    );
}

/// Private key output must be in PKCS#8 PEM format so that it can be loaded
/// directly by TLS stacks (rustls, openssl) and other tools without conversion.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn private_key_pem_is_pkcs8(#[case] out: ans_client::CsrOutput) {
    let key = out.private_key_pem.expose_secret();
    assert!(
        key.contains("BEGIN PRIVATE KEY"),
        "private key must be PKCS#8 (BEGIN PRIVATE KEY), got: {}",
        &key[..key.find('\n').unwrap_or(40)]
    );
}

// ── Secret handling ───────────────────────────────────────────────────────────

/// `CsrOutput` is routinely passed to `tracing::debug!(?output)`. The private
/// key must never appear in diagnostic output.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn debug_output_redacts_private_key(#[case] out: ans_client::CsrOutput) {
    let rendered = format!("{out:?}");
    let key = out.private_key_pem.expose_secret();

    assert!(
        !rendered.contains("BEGIN PRIVATE KEY"),
        "Debug output must not contain the PEM header"
    );
    for line in key.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            !rendered.contains(line),
            "Debug output leaked a private-key line: {line}"
        );
    }
    assert!(
        rendered.contains("REDACTED"),
        "Debug output should mark the key as redacted, got: {rendered}"
    );
    // The CSR itself is public and stays visible for diagnostics.
    assert!(rendered.contains("CERTIFICATE REQUEST"));
}

// ── Uniqueness ────────────────────────────────────────────────────────────────

/// Each call to `build()` must generate a fresh key pair so that two agents
/// running the same code never share a private key.
#[test]
fn two_server_csrs_differ() {
    let a = server_csr("agent.example.com", "1.0.0");
    let b = server_csr("agent.example.com", "1.0.0");

    assert_ne!(a.csr_pem, b.csr_pem, "each build must produce a unique CSR");
    assert_ne!(
        a.private_key_pem.expose_secret(),
        b.private_key_pem.expose_secret(),
        "each build must produce a unique private key"
    );
}

#[test]
fn two_identity_csrs_differ() {
    let a = identity_csr("agent.example.com", "1.0.0");
    let b = identity_csr("agent.example.com", "1.0.0");

    assert_ne!(a.csr_pem, b.csr_pem);
    assert_ne!(
        a.private_key_pem.expose_secret(),
        b.private_key_pem.expose_secret()
    );
}
