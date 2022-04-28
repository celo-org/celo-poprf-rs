use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};
use threshold_bls::group::PrimeOrder;

// Export polynomial library components used here so the caller may use them.
pub use threshold_bls::{
    group::{Element, Point, Scalar},
    poly::{Eval, Idx, Poly},
    sig::Share,
};

/// The `Scheme` trait contains the basic information of the groups over which the PRF operations
/// takes places and a way to create a valid key pair.
///
/// The Scheme trait is necessary to implement for "simple" tagged PRF scheme as well for threshold
/// based POPRF scheme.
pub trait Scheme: Debug {
    /// `Private` represents the field over which private keys are represented.
    type Private: Scalar<RHS = Self::Private>;
    /// `Public` represents the group over which the public keys are
    /// represented.
    type Public: Point<RHS = Self::Private> + Serialize + DeserializeOwned;
    /// `Evaluation` represents the group over which the evaluations are reresented.
    type Evaluation: Element<RHS = Self::Private> + PrimeOrder + Serialize + DeserializeOwned;

    // Returns a new fresh keypair usable by the scheme.
    fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);

        let mut public = Self::Public::one();
        public.mul(&private);

        (private, public)
    }
}

pub trait PrfScheme: Scheme {
    type Error: Error;

    /// Evaluates the PRF on the given plaintext tag and message input.
    ///
    /// Will result in the same value as calling `blind_msg`, `blind_eval`, `unblind_resp` in sequence.
    fn eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as PrfScheme>::Error>;
}

pub trait ThresholdScheme: PrfScheme {
    type Error: Error;

    // Returns a new fresh keypair usable by the scheme.
    fn threshold_keygen<R: RngCore>(
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> (Vec<Share<Self::Private>>, Poly<Self::Public>) {
        let private = Poly::<Self::Private>::new_from(t - 1, rng);
        let shares = (1..n + 1)
            .map(|i| private.eval(i as Idx))
            .map(|e| Share {
                index: e.index,
                private: e.value,
            })
            .collect();
        let polynomial = private.commit();

        (shares, polynomial)
    }

    /// Plaintext evaluation response share which can be aggregated to form a complete response.
    type PartialResp: Serialize + DeserializeOwned;

    /// Evaluates the POPRF over the plaintext message and tag with the provided **share** of the
    /// private key and returns the **partial** evaluation.
    ///
    /// # Arguments
    ///
    /// * private: Private key share to be used in evaluating the POPRF.
    /// * tag: Message tag passed into the evaluation of the POPRF.
    /// * msg: Plaintext message input.
    ///
    /// Returns a share of the evaluation over the tag and message, or an error if evaluation
    /// fails.
    ///
    /// # Safety
    ///
    /// In order for the decentralized security properties of the system to hold, the private key
    /// share input must be derived using a secure distributed key generation ceremony.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, ThresholdScheme}};
    /// let (shares, _) = Poprf::threshold_keygen(3, 2, &mut rand::thread_rng());
    /// let partial_resp = Poprf::partial_eval(&shares[0], b"public tag", b"public message")?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, <Self as ThresholdScheme>::Error>;

    /// Aggregates a vector of plaintext partial evaluations to a single threshold evaluation.
    ///
    /// # Arguments
    ///
    /// * threshold: The required number of evaluations shares to reconstruct the full response.
    /// * partials: A flattened array of partial evaluations.
    ///
    /// Returns the aggregated plaintext evaluation response, or an error if aggregation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, ThresholdScheme}};
    /// let (shares, polynomial) = Poprf::threshold_keygen(3, 2, &mut rand::thread_rng());
    /// let partial_resps = vec![
    ///     Poprf::partial_eval(&shares[0], b"public tag", b"public message")?,
    ///     Poprf::partial_eval(&shares[1], b"public tag", b"public message")?,
    /// ];
    /// let blinded_resp = Poprf::aggregate(2, &partial_resps)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn aggregate(
        threshold: usize,
        partials: &[Self::PartialResp],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error>;
}

pub trait PoprfScheme: Scheme {
    type Error: Error;

    /// Blinding factor which will be used to by the client unblind and verify the message.
    type Token: Serialize + DeserializeOwned;

    /// Blinded message type which is created by the client.
    type BlindMsg: Serialize + DeserializeOwned;

    /// Blinded response resulting from an evaluation on a blinded message and plaintext tag.
    type BlindResp: Serialize + DeserializeOwned;

    /// Plaintext evaluation response share which can be aggregated to form a complete response.
    type PartialResp: Serialize + DeserializeOwned;

    /// Blinded evaluation response share which can be aggregated to form a blind response.
    type BlindPartialResp: Serialize + DeserializeOwned;

    /// Given a message and an rng, it will blind the message and return the result.
    ///
    /// # Arguments
    ///
    /// * message: A plaintext message which you want to blind.
    /// * seed: An RNG to use to generate the random blinding factor e.g. rand::thread_rng.
    ///
    /// Returns a tuple with the blinding factor (token) and blinded message.
    ///
    /// # Safety
    ///
    /// If the same seed and message is used twice, the blinded result WILL be the same. In the
    /// Pith implementation, if two distinct messages are blinded with the same randomness, the
    /// blinding factor, and thus hashed message, can be extracted from the associated proof.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::PoprfScheme};
    /// let (token, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn blind_msg<R: RngCore>(
        msg: &[u8],
        rng: &mut R,
    ) -> Result<(Self::Token, Self::BlindMsg), Self::Error>;

    /// Evaluates the POPRF over the blinded message and plaintext tag with the provided private key
    /// and returns the blinded response
    ///
    /// # Arguments
    ///
    /// * private: Private key to be used in evaluating the POPRF.
    /// * tag: Message tag passed into the evaluation of the POPRF.
    /// * msg: Blinded message input containing the hidden message.
    ///
    /// Returns the blinded evaluation over the tag and blinded message, or an error is the
    /// evaluation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, Scheme}};
    /// let (private, _) = Poprf::keypair(&mut rand::thread_rng());
    /// let (_, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// let blinded_resp = Poprf::blind_eval(&private, b"public tag", &blinded_msg)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn blind_eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindResp, Self::Error>;

    /// Given a blinded evaluation response, the token from when the message was blinded, a
    /// public key and a tag, it unblinds and verifies the evaluation, returning the result which
    /// is a finalized POPRF evaluation.
    ///
    /// # Arguments
    ///
    /// * public: Public key against which the response should be verified.
    /// * token: The blinding factor used to blind the message.
    /// * tag: Message tag passed into the evaluation of the POPRF.
    /// * resp: A blinded POPRF evaluation response over the message and tag.
    ///
    /// Returns the unblinded POPRF evaluation, or an error if unblinding fails, including if
    /// verification against the provided public key and tag fails.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, Scheme}};
    /// let (private, public) = Poprf::keypair(&mut rand::thread_rng());
    /// let (token, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// let blinded_resp = Poprf::blind_eval(&private, b"public tag", &blinded_msg)?;
    /// let evaluation = Poprf::unblind_resp(&public, &token, b"public tag", &blinded_resp)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn unblind_resp(
        public: &Self::Public,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindResp,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Evaluates the POPRF over the blinded message and plaintext tag with the provided **share** of
    /// the private key and returns the **partial** evaluation.
    ///
    /// # Arguments
    ///
    /// * private: Private key share to be used in evaluating the POPRF.
    /// * tag: Message tag passed into the evaluation of the POPRF.
    /// * msg: Blinded message input containing the hidden message.
    ///
    /// Returns a share of the blinded evaluation over the tag and blinded message, or an error if
    /// the evaluation fails.
    ///
    /// # Safety
    ///
    /// In order for the decentralized security properties of the system to hold, the private key
    /// share input must be derived using a secure distributed key generation ceremony.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, ThresholdScheme}};
    /// let (shares, _) = Poprf::threshold_keygen(3, 2, &mut rand::thread_rng());
    /// let (_, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// let blinded_partial_resp = Poprf::blind_partial_eval(&shares[0], b"public tag", &blinded_msg)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, Self::Error>;

    /// Given a blinded partial evaluation response, the blinding factor from when the message was
    /// blinded, a public key polynomial and a tag, it unblinds and verifies the evaluation,
    /// returning the partial response which can then be aggregated.
    ///
    /// # Arguments
    ///
    /// * public: Public key polynomial against which the response should be verified.
    /// * token: The blinding_factor used to blind the message.
    /// * tag: Message tag passed into the evaluation of the POPRF.
    /// * resp: A blinded POPRF partial evaluation response over the message and tag.
    ///
    /// Returns the unblinded evaluation share, or an error is the unblinding fails, including due
    /// to verification failure.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, ThresholdScheme}};
    /// let (shares, polynomial) = Poprf::threshold_keygen(3, 2, &mut rand::thread_rng());
    /// let (token, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// let blinded_partial_resp = Poprf::blind_partial_eval(&shares[0], b"public tag", &blinded_msg)?;
    /// let partial_resp = Poprf::unblind_partial_resp(&polynomial, &token, b"public tag", &blinded_partial_resp)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, Self::Error>;

    /// Aggregates a vector of blind partial evaluations to a single blind threshold evaluation.
    ///
    /// # Arguments
    ///
    /// * threshold: The required number of evaluations shares to reconstruct the full response.
    /// * partials: A flattened array of blind partial evaluations.
    ///
    /// Returns the aggregated blind evaluation response, or an error if aggregation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use poprf::{Poprf, api::{PoprfScheme, ThresholdScheme}};
    /// let (shares, polynomial) = Poprf::threshold_keygen(3, 2, &mut rand::thread_rng());
    /// let (token, blinded_msg) = Poprf::blind_msg(b"secret message", &mut rand::thread_rng())?;
    /// let blinded_partial_resps = vec![
    ///     Poprf::blind_partial_eval(&shares[0], b"public tag", &blinded_msg)?,
    ///     Poprf::blind_partial_eval(&shares[1], b"public tag", &blinded_msg)?,
    /// ];
    /// let blinded_resp = Poprf::blind_aggregate(2, &blinded_partial_resps)?;
    /// # Ok::<(), poprf::PoprfError>(())
    /// ```
    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, Self::Error>;
}
