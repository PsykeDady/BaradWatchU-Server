// RFC 7250 requester implementation reused from Client remote.rs.
// Keep wire compatibility covered by cross-repository remote-service tests.

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    sign::{CertifiedKey, Signer, SigningKey},
    DigitallySignedStruct, Error, SignatureAlgorithm, SignatureScheme,
};
use std::sync::Arc;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), followed by the 32 bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub fn spki(public_key: &[u8; 32]) -> Vec<u8> {
    [&ED25519_SPKI_PREFIX[..], public_key].concat()
}

/// The Ed25519 key inside a raw-public-key "certificate"; None for anything else.
pub fn key_from_spki(der: &[u8]) -> Option<[u8; 32]> {
    der.strip_prefix(&ED25519_SPKI_PREFIX[..])?.try_into().ok()
}

pub fn provider() -> rustls::crypto::CryptoProvider {
    ring::default_provider()
}

pub(crate) fn algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

/// Verifies a TLS 1.3 CertificateVerify made with the presented raw Ed25519 key.
pub(crate) fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SignatureScheme::ED25519 || key_from_spki(cert.as_ref()).is_none() {
        return Err(Error::General(
            "only Ed25519 raw public keys are accepted".into(),
        ));
    }
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        &algorithms(),
    )
}

/// Ed25519 signing key for rustls; never printed.
pub struct Ed25519Key(Arc<ed25519_dalek::SigningKey>);

impl Ed25519Key {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self(Arc::new(key))
    }

    pub fn certified(self) -> CertifiedKey {
        let public = self.0.verifying_key().to_bytes();
        CertifiedKey::new(vec![CertificateDer::from(spki(&public))], Arc::new(self))
    }
}

impl std::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Key(..)")
    }
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(Ed25519Signer(self.0.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(spki(
            &self.0.verifying_key().to_bytes(),
        )))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct Ed25519Signer(Arc<ed25519_dalek::SigningKey>);

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Signer(..)")
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Requester side (the Server, or the test harness): accepts exactly one Client key,
/// the one recorded when the Client's public identity was imported out of band.
#[derive(Debug)]
struct PinnedClientKey([u8; 32]);

impl ServerCertVerifier for PinnedClientKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if intermediates.is_empty() && key_from_spki(end_entity.as_ref()) == Some(self.0) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// TLS configuration for a requester holding `requester_key` that talks to the Client
/// whose public key is `client_public_key`. Connect with server name = Device ID.
pub fn requester_config(
    requester_key: ed25519_dalek::SigningKey,
    client_public_key: [u8; 32],
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let certified = Arc::new(Ed25519Key::new(requester_key).certified());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedClientKey(client_public_key)))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified),
        ));
    Ok(Arc::new(config))
}
