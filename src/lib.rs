pub mod api;
pub mod ffi;

mod hash_to_field;
mod poprf;
mod poprfscheme;
mod prf;

use thiserror::Error;

/// Default POPRF instantiation.
pub type POPRF = bls12_377::G2Scheme;

/// BLS12-377 instantiations.
pub mod bls12_377 {
    use threshold_bls::curve::bls12377::PairingCurve;
    pub use threshold_bls::curve::bls12377::{G1Curve, G2Curve};

    /// Public Keys and messages on G2, tags on G1.
    pub type G2Scheme = super::poprf::G2Scheme<PairingCurve>;
}

#[derive(Debug, Error)]
pub enum POPRFError {
    #[error("could not hash to curve")]
    HashingError,

    #[error("could not serialize")]
    SerializationError(#[from] Box<bincode::ErrorKind>),

    #[error("not enough responses: {0}/{1}")]
    NotEnoughResponses(usize, usize),

    #[error("could not recover from shares")]
    RecoverError(#[from] threshold_bls::poly::PolyError),

    #[error("proof verification failed")]
    VerifyError,

    #[error("could not inverse")]
    NoInverse,
}
