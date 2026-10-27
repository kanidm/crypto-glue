use cipher::block_padding;
use crypto_glue::{
    aes256::{Aes256Key, new_key},
    aes256cbc::{Aes256CbcDec, Aes256CbcEnc, Aes256CbcIv, dec, enc},
    aes256cts::{
        Aes256CtsDec, Aes256CtsEnc, Aes256CtsIv, BlockModeDecrypt as _, BlockModeEncrypt as _,
        CtsDecrypt as _, CtsEncrypt as _, KeyIvInit as _,
    },
    aes256gcm::{Aead as _, Aes256Gcm, KeyInit as _, new_nonce},
    aes256kw::{Aes256Kw, Aes256KwWrapped},
    traits::{AeadInOut, Generate},
};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn aes256gcm_basic() {
    let aes256gcm_key = new_key();

    let cipher = Aes256Gcm::new(&aes256gcm_key);

    let nonce = new_nonce();

    // These are the "basic" encrypt/decrypt which postfixs a tag.
    let ciphertext = cipher
        .encrypt(&nonce, b"plaintext message".as_ref())
        .expect("Failed to encrypt message");
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Failed to decrypt message");

    assert_eq!(&plaintext, b"plaintext message");

    // For control of the tag, the following is used.

    // Never re-use nonces
    let nonce = new_nonce();

    let mut buffer = Vec::from(b"test message, super cool");

    // Same as "None"
    let associated_data = b"";

    let tag = cipher
        .encrypt_inout_detached(&nonce, associated_data, buffer.as_mut_slice().into())
        .expect("Failed to encrypt message");

    cipher
        .decrypt_inout_detached(&nonce, associated_data, buffer.as_mut_slice().into(), &tag)
        .expect("Failed to decrypt message");

    assert_eq!(buffer, b"test message, super cool");
}

#[test]
fn aes256cts_basic() {
    let key = new_key();
    let iv = Aes256CtsIv::generate();

    let enc = Aes256CtsEnc::new(&key, &iv);

    let original_buffer = b"plaintext message";
    let mut buffer = *original_buffer;

    enc.encrypt(&mut buffer).expect("encryption failed");

    assert_ne!(&buffer, original_buffer);

    let dec = Aes256CtsDec::new(&key, &iv);

    dec.decrypt(&mut buffer).expect("decryption failed");

    assert_eq!(&buffer, original_buffer);
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn aes256cbc_basic() {
    let key = new_key();
    let iv = Aes256CbcIv::generate();

    let enc = Aes256CbcEnc::new(&key, &iv);

    let ciphertext = enc.encrypt_padded_vec::<block_padding::Pkcs7>(b"plaintext message");

    let dec = Aes256CbcDec::new(&key, &iv);

    let plaintext = dec
        .decrypt_padded_vec::<block_padding::Pkcs7>(&ciphertext)
        .expect("Unpadding Failed");

    assert_eq!(plaintext, b"plaintext message");
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn aes256cbc_hmac_basic() {
    let key = new_key();

    let (mac, iv, ciphertext) =
        enc::<block_padding::Pkcs7>(&key, b"plaintext message").expect("Failed to encrypt message");

    let plaintext = dec::<block_padding::Pkcs7>(&key, &mac, &iv, &ciphertext)
        .expect("Failed to decrypt message");

    assert_eq!(plaintext, b"plaintext message");
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn aes256kw_basic() {
    let key_wrap_key = new_key();
    let key_wrap = Aes256Kw::new(&key_wrap_key);

    let key_to_wrap = new_key();
    let mut wrapped_key = Aes256KwWrapped::default();

    // Wrap it.
    key_wrap
        .wrap_key(&key_to_wrap, &mut wrapped_key)
        .expect("Failed to wrap key");
    // Reverse the process

    let mut key_unwrapped = Aes256Key::default();

    key_wrap
        .unwrap_key(&wrapped_key, &mut key_unwrapped)
        .expect("Failed to unwrap key");

    assert_eq!(key_to_wrap, key_unwrapped);
}
