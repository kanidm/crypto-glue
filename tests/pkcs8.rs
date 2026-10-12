use crypto_glue::{ecdsa_p256, traits::Pkcs8EncodePrivateKey};
use pkcs8::PrivateKeyInfoRef;

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn pkcs8_handling_test() {
    let ecdsa_priv_key = ecdsa_p256::new_key();
    let ecdsa_priv_key_der = ecdsa_priv_key
        .to_pkcs8_der()
        .expect("Failed to encode ECDSA private key");

    let priv_key_info = PrivateKeyInfoRef::try_from(ecdsa_priv_key_der.as_bytes())
        .expect("Failed to parse private key info");

    eprintln!("{priv_key_info:?}");
}
