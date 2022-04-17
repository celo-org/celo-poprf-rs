#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(all(feature = "wasm", feature = "parallel"))]
compile_error!("feature \"wasm\" and feature \"parrallel\" cannot be used together as WASM does not support threads.");

pub(crate) const PARTIAL_RESPONSE_LENGTH: usize = 580; // G_T element plus a u32 index.
pub(crate) const BLIND_PARTIAL_RESPONSE_LENGTH: usize = 1156; // 2 G_T elements plus a u32 index.
