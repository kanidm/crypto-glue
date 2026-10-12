use crypto_common::Key;
use crypto_common::Output;

use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
use sha2::digest::CtOutput;
use zeroize::Zeroizing;

pub type HmacSha256 = Hmac<Sha256>;

pub type HmacSha256Key = Zeroizing<Key<Hmac<Sha256>>>;

pub type HmacSha256Output = CtOutput<HmacSha256>;

pub type HmacSha256Bytes = Output<HmacSha256>;

pub fn new_key() -> HmacSha256Key {
    use crypto_common::Generate;
    Key::<HmacSha256>::generate().into()
}

pub fn oneshot(key: &HmacSha256Key, data: &[u8]) -> HmacSha256Output {
    use crypto_common::KeyInit;

    let mut hmac = HmacSha256::new(key);
    hmac.update(data);
    hmac.finalize()
}

#[allow(clippy::needless_pass_by_value)]
pub fn key_from_vec(bytes: Vec<u8>) -> Option<HmacSha256Key> {
    key_from_slice(&bytes)
}

pub fn key_from_slice(bytes: &[u8]) -> Option<HmacSha256Key> {
    use crypto_common::KeySizeUser;
    // Key too short - too long.
    if bytes.len() < 16 || bytes.len() > Hmac::<Sha256>::key_size() {
        None
    } else {
        let mut key = Key::<Hmac<Sha256>>::default();
        let key_ref = &mut key.as_mut_slice()[..bytes.len()];
        key_ref.copy_from_slice(bytes);
        Some(key.into())
    }
}

pub fn key_from_bytes(bytes: [u8; 64]) -> HmacSha256Key {
    Key::<Hmac<Sha256>>::from(bytes).into()
}

pub fn key_size() -> usize {
    use crypto_common::KeySizeUser;
    Hmac::<Sha256>::key_size()
}
