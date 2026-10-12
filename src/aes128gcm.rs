use aes::cipher::consts::{U12, U16};

pub use aes_gcm::aead::{Aead, AeadInOut, Payload};
pub use crypto_common::KeyInit;

pub use crate::aes128::Aes128Key;

pub type Aes128Gcm = aes_gcm::Aes128Gcm;

pub type Aes128GcmNonce = aes_gcm::Nonce<U12>;
pub type Aes128GcmTag = aes_gcm::Tag<U16>;

pub fn new_nonce() -> Aes128GcmNonce {
    use crypto_common::Generate;
    Aes128GcmNonce::generate()
}
