pub mod poprf;
mod hash_to_field;
mod traits;
use thiserror::Error;

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
