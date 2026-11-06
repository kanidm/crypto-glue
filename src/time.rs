//! Time functions.
use std::time::SystemTime;

/// [`SystemTime::now`][] equivalent that uses `Date.now()` on WASM.
#[cfg_attr(
    not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))),
    inline
)]
pub fn now() -> SystemTime {
    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    {
        use std::time::{Duration, UNIX_EPOCH};
        use wasm_bindgen::prelude::*;

        #[wasm_bindgen]
        extern "C" {
            // NOTE: This signature works around https://bugzilla.mozilla.org/show_bug.cgi?id=1787770
            #[wasm_bindgen(js_namespace = Date, catch)]
            fn now() -> Result<f64, JsValue>;
        }

        let now = now().unwrap_throw() as u64;
        UNIX_EPOCH + Duration::from_millis(now)
    }

    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    SystemTime::now()
}
