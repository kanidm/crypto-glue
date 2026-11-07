//! Time functions.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Return the [Duration] since the [UNIX epoch][UNIX_EPOCH].
///
/// Returns a zero duration if the current system time is set to before the epoch.
///
/// On WASM targets, throws a WASM-level exception if `Date.now()` is not available.
pub fn time_since_epoch() -> Duration {
    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    {
        use wasm_bindgen::prelude::*;

        #[wasm_bindgen]
        extern "C" {
            // NOTE: This signature works around https://bugzilla.mozilla.org/show_bug.cgi?id=1787770
            #[wasm_bindgen(js_namespace = Date, catch)]
            fn now() -> Result<f64, JsValue>;
        }

        let now = now().unwrap_throw() as u64;
        Duration::from_millis(now)
    }

    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

/// [`SystemTime::now`][] equivalent that uses `Date.now()` on WASM.
#[cfg_attr(
    not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))),
    inline
)]
pub fn now() -> SystemTime {
    #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
    {
        UNIX_EPOCH + time_since_epoch()
    }

    #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
    SystemTime::now()
}
