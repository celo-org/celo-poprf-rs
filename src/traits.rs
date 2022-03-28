use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};
use threshold_bls::{
    group::{Element, Point, Scalar},
    poly::Poly,
    sig::Share,
};
use crate::poprf::poprf::POPRFInterface;
use crate::POPRFError;
use crate::poprf::Scheme;

/// The `Scheme` trait contains the basic information of the groups over which the PRF operations
/// takes places and a way to create a valid key pair.
///
/// The Scheme trait is necessary to implement for "simple" tagged PRF scheme as well for threshold
/// based POPRF scheme.
// TODO: Make keypair a function in POPRFInterface, add keygen APIs to PRFScheme and POPRFScheme
// TODO: Add this back with better trait bounds?
/*pub trait Scheme: Debug {
    /// `Private` represents the field over which private keys are represented.
    type Private: Scalar<RHS = Self::Private>;
    /// `Public` represents the group over which the public keys are
    /// represented.
    type Public: Point<RHS = Self::Private> + Serialize + DeserializeOwned;
    /// `Evaluation` represents the group over which the evaluations are reresented.
    type Evaluation: Element<RHS = Self::Private> + Serialize + DeserializeOwned;

    /// Returns a new fresh keypair usable by the scheme.
    fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);

        let mut public = Self::Public::one();
        public.mul(&private);

        (private, public)
    }
}*/

/*impl<C> Scheme for C
where
    C : POPRFInterface + Debug
{
    type Private = C::Scalar;
    type Public = C::G2;
    type Evaluation = C::GT;
}*/

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

    /// The blinded message type which is created by the client.
    type BlindMsg: Serialize + DeserializeOwned;

    /// The blinded response type which results from an eval on a blinded message and plaintext tag.
    type BlindResp: Serialize + DeserializeOwned;

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
}

impl<C> POPRFScheme for C
where
    C : POPRFInterface + Debug,
{
    type Error = POPRFError;
    type Token = (C::Private, C::Private, C::Private);
    type BlindMsg = (C::Private, C::Private, C::Private, C::Public, C::Public);
    type BlindResp = (C::Evaluation, C::Evaluation);

    fn blind_msg(msg: &[u8]) -> Result<(Self::Token, Self::BlindMsg), Self::Error> {
        let (r,c,d,a,b) = C::req(msg).unwrap();
        let mut c_div_r = c.clone();
        let r_inv = r.inverse().ok_or(Self::Error::NoInverse).unwrap();
        c_div_r.mul(&r_inv);
        let (z,s_1,s_2) = C::prove(&mut a.clone(),&b,&mut c_div_r.clone(),&mut d.clone()).unwrap();
        let token = (r,c,d);
        let blmsg = (z,s_1,s_2,a,b);
        Ok((token, blmsg))
    }

    fn blind_eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindResp, Self::Error> {
        let (z,s_1,s_2,a,b) = msg;
        let bool = C::verify(&mut a.clone(), &mut b.clone(), &z, &s_1, &s_2)?;
        let (A,B) = C::blind_ev(private, tag, a, b)?;
        Ok((A,B))
    }

    fn unblind_resp(
        public: &Self::Public,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindResp,
    ) -> Result<Vec<u8>, Self::Error> {
        let (r,c,d) = token;
        let (A,B) = resp;
        let res = C::finalize(public, A, B, tag, r, c, d);

        // TODO: Hash output
        Ok(Vec::<u8>::new())
    }

}

pub trait ThresholdScheme: POPRFScheme {
    /// Error produced when partially signing, aggregating or verifying
    type Error: Error;

    type PartialResp: Serialize + DeserializeOwned;

    /// Partially signs a message with a share of the private key.
    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, <Self as ThresholdScheme>::Error>;

    /// Aggregates all partials signature together. Note that this method does
    /// not verify if the partial signatures are correct or not; it only
    /// aggregates them.
    fn aggregate(threshold: usize, partials: &[Self::PartialResp]) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error>;
}

/*pub trait BlindThresholdScheme: ThresholdScheme {
    /// Error produced when partially signing, aggregating or verifying
    type Error: Error;

    type BlindPartialResp: Serialize + DeserializeOwned;

    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, <Self as BlindThresholdScheme>::Error>;

    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, <Self as BlindThresholdScheme>::Error>;

    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, <Self as BlindThresholdScheme>::Error>;
}

impl<C> BlindThresholdScheme for C
where
    C: POPRFInterface + ThresholdScheme + Debug,
{
    type Error = POPRFError;

    type BlindPartialResp = Share<(C::Evaluation, C::Evaluation)>;

    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, <Self as BlindThresholdScheme>::Error> {
        let (z,s_1,s_2,a,b) = msg;
        let bool = C::verify(&mut a.clone(), &mut b.clone(), &z, &s_1, &s_2)?;
        let (A,B) = C::blind_ev(&private.private, tag, a, b)?;
        Ok((A,B, private.index))
    }

    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, <Self as BlindThresholdScheme>::Error> {
        let (r,c,d) = token;
        let (A,B) = resp.private;
        let res = C::finalize(public, A, B, tag, r, c, d);
        Ok((res, resp.index))
    }

    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, <Self as BlindThresholdScheme>::Error> {
    }
}*/
