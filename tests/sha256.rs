use crypto_glue::{s256::*, traits::*};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")),
    wasm_bindgen_test
)]
fn sha256_basic() {
    let mut hasher = Sha256::new();
    hasher.update([0, 1, 2, 3]);
    let out: Sha256Output = hasher.finalize();
    assert_eq!(
        out,
        [
            0x05, 0x4e, 0xde, 0xc1, 0xd0, 0x21, 0x1f, 0x62, 0x4f, 0xed, 0x0c, 0xbc, 0xa9, 0xd4,
            0xf9, 0x40, 0x0b, 0x0e, 0x49, 0x1c, 0x43, 0x74, 0x2a, 0xf2, 0xc5, 0xb0, 0xab, 0xeb,
            0xf0, 0xc9, 0x90, 0xd8
        ]
    );
}
