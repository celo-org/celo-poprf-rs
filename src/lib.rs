pub mod api;
pub mod ffi;

mod hash_to_field;
mod poprf;
mod poprfscheme;
mod prf;
use bls_crypto::BLSError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum POPRFError {
    //#[error("could not hash to curve")]
    //HashingError(#[from] bls_crypto::BLSError),
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
