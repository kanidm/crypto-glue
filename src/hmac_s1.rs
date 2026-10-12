use crypto_common::{Key, Output};
use hmac::{Hmac, Mac};
use sha1::{Sha1, digest::CtOutput};
use zeroize::Zeroizing;

pub type HmacSha1 = Hmac<Sha1>;

pub type HmacSha1Key = Zeroizing<Key<Hmac<Sha1>>>;

pub type HmacSha1Output = CtOutput<HmacSha1>;

pub type HmacSha1Bytes = Output<HmacSha1>;

pub fn new_key() -> HmacSha1Key {
    use crypto_common::Generate;
    Key::<HmacSha1>::generate().into()
}

pub fn oneshot(key: &HmacSha1Key, data: &[u8]) -> HmacSha1Output {
    use crypto_common::KeyInit;

    let mut hmac = HmacSha1::new(key);
    hmac.update(data);
    hmac.finalize()
}

#[allow(clippy::needless_pass_by_value)]
pub fn key_from_vec(bytes: Vec<u8>) -> Option<HmacSha1Key> {
    key_from_slice(&bytes)
}

pub fn key_from_slice(bytes: &[u8]) -> Option<HmacSha1Key> {
    use crypto_common::KeySizeUser;
    // Key too short - too long.
    if bytes.len() < 16 || bytes.len() > Hmac::<Sha1>::key_size() {
        None
    } else {
        let mut key = Key::<Hmac<Sha1>>::default();
        let key_ref = &mut key.as_mut_slice()[..bytes.len()];
        key_ref.copy_from_slice(bytes);
        Some(key.into())
    }
}

pub fn key_from_bytes(bytes: [u8; 64]) -> HmacSha1Key {
    Key::<Hmac<Sha1>>::from(bytes).into()
}

pub fn key_size() -> usize {
    use crypto_common::KeySizeUser;
    Hmac::<Sha1>::key_size()
}
