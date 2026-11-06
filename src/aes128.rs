use aes::Aes128;
use crypto_common::{Key, KeySizeUser};
use zeroize::Zeroizing;

pub type Aes128Key = Zeroizing<Key<Aes128>>;

pub fn key_size() -> usize {
    Aes128::key_size()
}

pub fn key_from_slice(bytes: &[u8]) -> Option<Aes128Key> {
    Key::<Aes128>::try_from(bytes).ok().map(|key| key.into())
}

pub fn key_from_bytes(bytes: [u8; 16]) -> Aes128Key {
    Key::<Aes128>::from(bytes).into()
}

pub fn new_key() -> Aes128Key {
    use crypto_common::Generate;
    Key::<Aes128>::generate().into()
}
