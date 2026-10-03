use crypto_glue::ecdh_p256::*;

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn ecdh_p256_basic() {
    let secret_a = new_secret();
    let secret_b = new_secret();

    let public_a = secret_a.public_key();
    let public_b = secret_b.public_key();

    let derived_secret_a = secret_a.diffie_hellman(&public_b);
    let derived_secret_b = secret_b.diffie_hellman(&public_a);

    assert_eq!(
        derived_secret_a.raw_secret_bytes(),
        derived_secret_b.raw_secret_bytes()
    );
}
