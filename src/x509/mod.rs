pub use self::chain::{X509Store, X509VerificationError};
pub use self::display::X509Display;
pub use const_oid::db as oiddb;
pub use der::asn1::BitString;
pub use x509_cert::builder::RequestBuilder as CertificateRequestBuilder;
pub use x509_cert::builder::{Builder, CertificateBuilder, Profile};
pub use x509_cert::certificate::Certificate;
pub use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
pub use x509_cert::name::Name;
pub use x509_cert::request::CertReq as CertificateRequest;
pub use x509_cert::serial_number::SerialNumber;
pub use x509_cert::spki::{
    AlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
pub use x509_cert::time::{Time, Validity};

use crate::{
    ecdsa_p256::{EcdsaP256PublicKey, EcdsaP256Signature, EcdsaP256VerifyingKey},
    ecdsa_p384::{EcdsaP384PublicKey, EcdsaP384Signature, EcdsaP384VerifyingKey},
    rsa::{RS256PublicKey, RS256Signature, RS256VerifyingKey},
    traits::{OwnedToRef, Verifier},
};
use tracing::error;

mod chain;
mod display;

pub fn uuid_to_serial(serial_uuid: uuid::Uuid) -> SerialNumber {
    let mut serial_bytes: [u8; 17] = [0; 17];
    // The first byte must be a value else if the leading byte is a null then
    // der is unhappy.
    serial_bytes[0] = 0x01;
    let update_bytes = &mut serial_bytes[1..];
    update_bytes.copy_from_slice(serial_uuid.as_bytes());

    #[allow(clippy::expect_used)]
    SerialNumber::new(&serial_bytes).expect("Failed to create serial number from uuid")
}

pub fn x509_verify_signature(
    data: &[u8],
    signature: &[u8],
    certificate: &Certificate,
) -> Result<(), X509VerificationError> {
    let subject_public_key_info = certificate
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();

    match certificate.tbs_certificate.signature.oid {
        oiddb::rfc5912::ECDSA_WITH_SHA_256 => {
            let signature = EcdsaP256Signature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = EcdsaP256PublicKey::try_from(subject_public_key_info)
                .map(EcdsaP256VerifyingKey::from)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        oiddb::rfc5912::ECDSA_WITH_SHA_384 => {
            let signature = EcdsaP384Signature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = EcdsaP384PublicKey::try_from(subject_public_key_info)
                .map(EcdsaP384VerifyingKey::from)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        oiddb::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            let signature = RS256Signature::try_from(signature)
                .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

            let verifier = RS256PublicKey::try_from(subject_public_key_info)
                .map(RS256VerifyingKey::new)
                .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

            verifier
                .verify(data, &signature)
                .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
        }
        algo_oid => {
            error!(?algo_oid);
            return Err(X509VerificationError::SignatureAlgorithmNotImplemented);
        }
    }

    Ok(())
}
