// RFC 7250 Ed25519 raw-public-key primitives shared with the Client tunnel.

use rustls::{
    client::danger::HandshakeSignatureValid,
    crypto::{ring, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
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
