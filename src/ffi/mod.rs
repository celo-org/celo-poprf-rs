#[cfg(feature = "wasm")]
pub mod wasm;

use crate::{ POPRF, poprf::Scheme };

pub type PublicKey = <POPRF as Scheme>::Public;
pub type PrivateKey = <POPRF as Scheme>::Private;

pub(crate) const PARTIAL_RESPONSE_LENGTH: usize = std::mem::size_of(POPRF::PartialResp);
pub(crate) const BLIND_PARTIAL_RESPONSE_LENGTH: usize = std::mem::size_of(POPRF::BlindPartialResp);
