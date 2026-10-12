use crypto_glue::{rsa::*, traits::*};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn rsa_basic() {
    let pkey = new_key(MIN_BITS).expect("Failed to generate RSA key");

    let pubkey = RS256PublicKey::from(&pkey);

    // OAEP

    let ciphertext =
        oaep_sha256_encrypt(&pubkey, b"this is a message").expect("Failed to encrypt message");

    let plaintext = oaep_sha256_decrypt(&pkey, &ciphertext).expect("Failed to decrypt message");

    assert_eq!(plaintext, b"this is a message");

    // PKCS1.5 Sig
    let signing_key = RS256SigningKey::new(pkey);
    let verifying_key = RS256VerifyingKey::new(pubkey);

    let mut rng = rand::rng();

    let data = b"Fully sick data to sign mate.";

    let signature = signing_key.sign_with_rng(&mut rng, data);
    assert!(verifying_key.verify(data, &signature).is_ok());

    let signature = signing_key.sign(data);
    assert!(verifying_key.verify(data, &signature).is_ok());
}
