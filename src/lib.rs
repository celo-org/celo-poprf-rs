pub mod api;
pub mod ffi;

mod hash_to_field;
mod poprf;
mod poprfscheme;
mod prf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum POPRFError {
    #[error("could not hash to curve")]
    HashingError,

    #[error("could not hash to scalar field")]
    HashError(#[from] crate::hash_to_field::HashError),

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

///////////////////////////////////////////////////////////////////////////
// Export default instantiation and associated types for ease of use.
///////////////////////////////////////////////////////////////////////////

/// BLS12-377 instantiations.
pub mod bls12_377 {
    use threshold_bls::curve::bls12377::PairingCurve;
    pub use threshold_bls::curve::bls12377::{G1Curve, G2Curve};

    /// Public Keys and messages on G2, tags on G1.
    pub type G2Scheme = super::poprf::G2Scheme<PairingCurve>;
}

use crate::{api::POPRFScheme, poprf::Scheme};

pub type POPRF = bls12_377::G2Scheme;

pub type PublicKey = <POPRF as Scheme>::Public;
pub type PrivateKey = <POPRF as Scheme>::Private;

/// The blinding factor which will be used to unblind and verify the message.
pub type Token = <POPRF as POPRFScheme>::Token;

/// The blinded message type which is created by the client.
pub type BlindMsg = <POPRF as POPRFScheme>::BlindMsg;

/// The blinded response type which results from an eval on a blinded message and plaintext tag.
pub type BlindResp = <POPRF as POPRFScheme>::BlindResp;

/// The partial response type
pub type PartialResp = <POPRF as POPRFScheme>::PartialResp;

/// The blind partial response type
pub type BlindPartialResp = <POPRF as POPRFScheme>::BlindPartialResp;
