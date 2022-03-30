#[cfg(feature = "wasm")]
pub mod wasm;

use crate::{BlindPartialResp, PartialResp};

pub(crate) const PARTIAL_RESPONSE_LENGTH: usize = std::mem::size_of::<PartialResp>();
pub(crate) const BLIND_PARTIAL_RESPONSE_LENGTH: usize = std::mem::size_of::<BlindPartialResp>();
