/*#[cfg(feature = "wasm")]
pub mod wasm;

use crate::{poly::Idx, poprf::POPRF, traits::Scheme};

pub type PublicKey = <POPRF as Scheme>::Public;
pub type PrivateKey = <POPRF as Scheme>::Private;

pub const VEC_LENGTH: usize = 8;
pub const SIGNATURE_LEN: usize = 48;
pub const PARTIAL_SIG_LENGTH: usize =
    VEC_LENGTH + SIGNATURE_LEN + std::mem::size_of::<Idx>();*/
