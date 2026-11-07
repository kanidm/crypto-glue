pub use aes_gcm::aead::AeadInOut;
pub use crypto_common::{Generate, KeyInit, OutputSizeUser};
pub use der::{
    Decode as DecodeDer, DecodePem, Encode as EncodeDer, EncodePem,
    pem::LineEnding as LineEndingPem, referenced::OwnedToRef,
};
pub use digest::FixedOutput;
pub use elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
pub use hmac::{Hmac, Mac};
pub use pkcs8::{
    DecodePrivateKey as Pkcs8DecodePrivateKey, EncodePrivateKey as Pkcs8EncodePrivateKey,
};
pub use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey as Pkcs1DecodeRsaPrivateKey,
        EncodeRsaPrivateKey as Pkcs1EncodeRsaPrivateKey,
    },
    signature::{
        DigestSigner, DigestVerifier, Keypair, RandomizedSigner, SignatureEncoding, Signer,
        Verifier,
    },
    traits::PublicKeyParts,
};
pub use sha2::Digest;
pub use spki::{
    DecodePublicKey as SpkiDecodePublicKey, DynSignatureAlgorithmIdentifier,
    EncodePublicKey as SpkiEncodePublicKey,
};
pub use x509_cert::ext::ToExtension;
pub use zeroize::Zeroizing;

pub mod hazmat {
    //! This is a “Hazardous Materials” module. You should ONLY use it if you’re 100% absolutely sure that you know what you’re doing because this module is full of land mines, dragons, and dinosaurs with laser guns.

    pub use rsa::signature::hazmat::PrehashVerifier;
}
