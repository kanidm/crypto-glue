use aes::cipher::{Array, BlockSizeUser};
use crypto_common::{Generate, Key, KeySizeUser};
use zeroize::Zeroizing;

pub use aes::{
    Aes256,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt},
};

pub type Aes256Key = Zeroizing<Key<Aes256>>;
pub type Aes256BlockSize = <Aes256 as BlockSizeUser>::BlockSize;
pub type Aes256Block = Array<u8, <Aes256 as BlockSizeUser>::BlockSize>;

pub fn key_size() -> usize {
    Aes256::key_size()
}

pub fn key_from_slice(bytes: &[u8]) -> Option<Aes256Key> {
    Key::<Aes256>::try_from(bytes).ok().map(|key| key.into())
}

pub fn key_from_bytes(bytes: [u8; 32]) -> Aes256Key {
    Key::<Aes256>::from(bytes).into()
}

pub fn new_key() -> Aes256Key {
    Key::<Aes256>::generate().into()
}
