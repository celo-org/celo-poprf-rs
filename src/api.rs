use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};
use threshold_bls::{
    group::{Element, Scalar},
    poly::Poly,
    sig::{Share},
};
use crate::poprf::poprf::POPRF;
use crate::POPRFError;
use crate::poprf::Scheme;

pub trait PRFScheme: Scheme {
    type Error: Error;

    /// Evaluates the PRF on the given plaintext tag and message input.
    ///
    /// Will result in the same value as calling `blind_msg`, `blind_eval`, `unblind_resp` in sequence.
    fn eval(private: &Self::Private, tag: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait POPRFScheme: Scheme {
    type Error: Error;

    /// The blinding factor which will be used to unblind and verify the message.
    type Token: Serialize + DeserializeOwned;

    type Proof: Serialize + DeserializeOwned;

    /// The blinded message type which is created by the client.
    type BlindMsg: Serialize + DeserializeOwned;

    /// The blinded response type which results from an eval on a blinded message and plaintext tag.
    type BlindResp: Serialize + DeserializeOwned;

    /// The unblinded response type which results from unblinding a blinded response
    type Resp: Serialize + DeserializeOwned;

    /// The partial response type
    type PartialResp: Serialize + DeserializeOwned; 

    /// The blind partial response type
    type BlindPartialResp: Serialize + DeserializeOwned;

    //fn blind_msg<R: RngCore>(msg: &[u8], rng: &mut R) -> (Self::Token, Self::BlindMsg);
    fn blind_msg(msg: &[u8]) -> Result<(Self::Token, Self::BlindMsg), Self::Error>;

    fn blind_eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindResp, Self::Error>;

    fn unblind_resp(
        public: &Self::Public,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindResp,
    ) -> Result<Vec<u8>, Self::Error>; 

    /// Partially signs a message with a share of the private key.
    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, Self::Error>;

    /// Aggregates all partials signature together. Note that this method does
    /// not verify if the partial signatures are correct or not; it only
    /// aggregates them.
    fn aggregate(threshold: usize, partials: &[Self::PartialResp]) -> Result<Vec<u8>, Self::Error>;

    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, Self::Error>;

    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, Self::Error>;

    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, Self::Error>;
}
