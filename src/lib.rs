pub mod poprf;
mod hash_to_field;
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
    RecoverError,

    #[error("could not inverse")]
    NoInverse,
}
