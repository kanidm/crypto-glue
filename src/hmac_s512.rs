use crypto_common::{Key, Output};
use hmac::Hmac;
use sha2::{Sha512, digest::CtOutput};
use zeroize::Zeroizing;

pub use hmac::Mac;

pub type HmacSha512 = Hmac<Sha512>;

pub type HmacSha512Key = Zeroizing<Key<Hmac<Sha512>>>;

pub type HmacSha512Output = CtOutput<HmacSha512>;

pub type HmacSha512Bytes = Output<HmacSha512>;

pub fn new_hmac_sha512_key() -> HmacSha512Key {
    use crypto_common::Generate;
    Key::<HmacSha512>::generate().into()
}

pub fn oneshot(key: &HmacSha512Key, data: &[u8]) -> HmacSha512Output {
    use crypto_common::KeyInit;

    let mut hmac = HmacSha512::new(key);
    hmac.update(data);
    hmac.finalize()
}

pub fn key_from_slice(bytes: &[u8]) -> Option<HmacSha512Key> {
    use crypto_common::KeySizeUser;
    // Key too short - too long.
    if bytes.len() < 16 || bytes.len() > Hmac::<Sha512>::key_size() {
        None
    } else {
        let mut key = Key::<Hmac<Sha512>>::default();
        let key_ref = &mut key.as_mut_slice()[..bytes.len()];
        key_ref.copy_from_slice(bytes);
        Some(key.into())
    }
}

pub fn key_size() -> usize {
    use crypto_common::KeySizeUser;
    Hmac::<Sha512>::key_size()
}
