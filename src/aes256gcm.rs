use aes::{
    Aes256,
    cipher::consts::{U12, U16},
};
use aes_gcm::AesGcm;

pub use aes_gcm::aead::{Aead, AeadInOut, Payload};
pub use crypto_common::KeyInit;

pub use crate::aes256::Aes256Key;

// Same as  AesGcm<Aes256, U12, U16>;
pub type Aes256Gcm = aes_gcm::Aes256Gcm;

pub type Aes256GcmN16 = AesGcm<Aes256, U16, U16>;
pub type Aes256GcmNonce16 = aes_gcm::Nonce<U16>;

pub type Aes256GcmNonce = aes_gcm::Nonce<U12>;
pub type Aes256GcmTag = aes_gcm::Tag<U16>;

pub fn new_nonce() -> Aes256GcmNonce {
    use crypto_common::Generate;
    Aes256GcmNonce::generate()
}
