use crypto_glue::{
    hmac_s256::{HmacSha256, new_key},
    hmac_s512::{HmacSha512, new_hmac_sha512_key},
    traits::{KeyInit, Mac},
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
fn hmac_256_basic() {
    let hmac_key = new_key();

    let mut hmac = HmacSha256::new(&hmac_key);
    hmac.update(&[0, 1, 2, 3]);
    let out = hmac.finalize();

    eprintln!("{:?}", out.into_bytes());
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn hmac_512_basic() {
    let hmac_key = new_hmac_sha512_key();

    let mut hmac = HmacSha512::new(&hmac_key);
    hmac.update(&[0, 1, 2, 3]);
    let out = hmac.finalize();

    eprintln!("{:?}", out.into_bytes());
}
