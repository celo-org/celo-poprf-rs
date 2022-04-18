#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(all(feature = "wasm", feature = "parallel"))]
compile_error!("feature \"wasm\" and feature \"parrallel\" cannot be used together as WASM does not support threads.");

// A println! style macro to allow output to the JS console.
// ```rust
// crate::ffi::console_log!("hello from {}", "rust!");
// ```
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => {
        #[cfg(feature = "wasm-debug")]
        web_sys::console::log_1(&format_args!($($t)*).to_string().into());
    }
}

// Export this macro to the crate unconditionally on whether WASM support is enabled for ease of
// use in devlopement (i.e. so a developer can simply add `crate::ffi::console_log!(...)` when
// needed to help with debugging usage in WASM.
#[allow(unused_imports)]
pub(crate) use console_log;
