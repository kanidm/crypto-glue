pub use argon2;
pub use hex;
pub use zeroize;
pub use rand;

pub mod prelude {

}


pub mod hmac {
    use sha2::Sha256;
    use sha2::digest::CtOutput;
    use crypto_common::Key;
    use hmac::Hmac;
    use zeroize::Zeroizing;

    pub use hmac::Mac;

    pub type HmacSha256 = Hmac<Sha256>;

    pub type HmacSha256Key = Zeroizing<Key<Hmac<Sha256>>>;

    pub type HmacSha256Output = CtOutput<HmacSha256>;

    pub fn new_hmac_sha256_key() -> HmacSha256Key {
        use crypto_common::KeyInit;

        let mut rng = rand::thread_rng();
        HmacSha256::generate_key(&mut rng).into()
    }

    pub fn hmac_sha256_oneshot(
        key: &HmacSha256Key,
        data: &[u8],
    ) -> HmacSha256Output {
        let mut hmac = HmacSha256::new(&key);
        hmac.update(data);
        hmac.finalize()
    }
}

pub mod aes256gcm {
    use aes_gcm::{
        aead::AeadCore,
        Key,
    };
    use generic_array::GenericArray;
    use zeroize::Zeroizing;
    use aes::cipher::consts::{U12, U16};

    pub use crypto_common::KeyInit;
    pub use aes_gcm::{
        aead::{
            Aead,
            AeadInPlace,
            Payload,
        }
    };

    pub type Aes256Gcm = aes_gcm::Aes256Gcm;

    pub type Aes256GcmKey = Zeroizing<Key<Aes256Gcm>>;

    pub type Aes256GcmNonce = GenericArray<u8, U12>;

    pub type Aes256GcmTag = GenericArray<u8, U16>;

    pub fn new_aes256gcm_key() -> Aes256GcmKey {
        let mut rng = rand::thread_rng();
        Aes256Gcm::generate_key(&mut rng).into()
    }

    pub fn new_aes256gcm_nonce() -> Aes256GcmNonce {
        let mut rng = rand::thread_rng();

        Aes256Gcm::generate_nonce(&mut rng)
    }
}


pub mod aes256cbc {

}

pub mod aes256kw {
    use generic_array::GenericArray;
    use aes::cipher::consts::{U32, U40};
    use aes::Aes256;
    use zeroize::Zeroizing;

    pub use crypto_common::KeyInit;

    pub type Aes256Kw = aes_kw::KekAes256;

    pub type Aes256KwKey = Zeroizing<GenericArray<u8, U32>>;

    pub type Aes256KwWrapped = GenericArray<u8, U40>;

    pub fn new_aes256kw_key() -> Aes256KwKey {
        let mut rng = rand::thread_rng();
        Aes256::generate_key(&mut rng).into()
    }
}



#[cfg(test)]
mod tests {

    #[test]
    fn hmac_basic() {
        use crate::hmac::*;

        let hmac_key = new_hmac_sha256_key();

        let mut hmac = HmacSha256::new(&hmac_key);
        hmac.update(&[0,1,2,3]);
        let out = hmac.finalize();

        eprintln!("{:?}", out.into_bytes());
    }

    #[test]
    fn aes256gcm_basic() {
        use crate::aes256gcm::*;

        let aes256gcm_key = new_aes256gcm_key();

        let cipher = Aes256Gcm::new(&aes256gcm_key);

        let nonce = new_aes256gcm_nonce();

        // These are the "basic" encrypt/decrypt which postfixs a tag.
        let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
            .unwrap();

        assert_eq!(&plaintext, b"plaintext message");

        // For control of the tag, the following is used.

        // Never re-use nonces
        let nonce = new_aes256gcm_nonce();

        let mut buffer = Vec::from(b"test message, super cool");

        // Same as "None"
        let associated_data = b"";

        let tag = cipher.encrypt_in_place_detached(
            &nonce,
            associated_data,
            buffer.as_mut_slice(),
        ).unwrap();

        cipher.decrypt_in_place_detached(
            &nonce,
            associated_data,
            &mut buffer,
            &tag,
        ).unwrap();

        assert_eq!(buffer, b"test message, super cool");
    }

    #[test]
    fn aes256cbc_basic() {

    }

    #[test]
    fn aes256kw_basic() {
        use crate::aes256kw::*;

        let key_wrap_key = new_aes256kw_key();
        let key_wrap = Aes256Kw::new(&key_wrap_key);

        let key_to_wrap = new_aes256kw_key();
        let mut wrapped_key = Aes256KwWrapped::default();

        // Wrap it.
        key_wrap.wrap(&key_to_wrap, &mut wrapped_key).unwrap();
        // Reverse the process

        let mut key_unwrapped = Aes256KwKey::default();

        key_wrap.unwrap(&wrapped_key, &mut key_unwrapped).unwrap();

        assert_eq!(key_to_wrap, key_unwrapped);
    }
}

