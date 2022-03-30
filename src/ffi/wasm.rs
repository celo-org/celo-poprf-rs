//! # BLS12-377 WASM Bindings for the POPRF
use wasm_bindgen::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use blake2::{Blake2s256, Digest};

use threshold_bls::{poly::Idx, schemes::bls12_377::G2Scheme as SigScheme, sig::Scheme};

use crate::{
    poprf::POPRF,
    ffi::{PublicKey, PrivateKey, PARTIAL_SIG_LENGTH},
    poly::{Idx as Index, Poly},
    traits::{
        Share, Scheme, PRFScheme, POPRFScheme, ThresholdScheme, BlindThresholdScheme,
    },
};

type Result<T> = std::result::Result<T, JsValue>;

///////////////////////////////////////////////////////////////////////////
// User -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Given a message and a seed, it will blind it and return the blinded message
///
/// * message: A cleartext message which you want to blind
/// * seed: A 32 byte seed for randomness. You can get one securely via `crypto.randomBytes(32)`
///
/// Returns a `BlindedMessage`. The `BlindedMessage.blinding_factor` should be saved for unblinding any
/// evaluations on `BlindedMessage.message`
///
/// # Safety
///
/// - If the same seed is used twice, the blinded result WILL be the same
pub fn blind(message: &[u8], seed: &[u8]) -> BlindedMessage {
    // convert the seed to randomness
    let mut rng = get_rng(&[message, seed]);

    // blind the message with this randomness
    let (blinding_factor, blinded_message) = POPRF::blind_msg(message, &mut rng);

    // return the message and the blinding_factor used for blinding
    BlindedMessage {
        message: blinded_message,
        blinding_factor,
    }
}

#[wasm_bindgen]
/// Given a blinded evaluation response, the blinding_factor from when the message was blinded, a
/// public key and a tag, it unblinds and verifies the evaluation, returning the result.
///
/// * public_key: Public key against which the response should be verified.
/// * blinding_factor: The blinding_factor used to blind the message.
/// * tag: Message tag passed into the evaluation of the POPRF.
/// * blinded_resp: A message which has been blinded or a blind signature.
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If unblinding fails, including verification failure.
pub fn unblind(public_key_buf: &[u8], blinding_factor_buf: &[u8], tag: &[u8], blinded_resp_buf: &[u8]) -> Result<Vec<u8>> {
    let public_key: PublicKey = bincode::deserialize(public_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize public key {}", err)))?;

    let blinded_resp: POPRF::BlindResp = bincode::deserialize(blinded_resp_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize blinded response {}", err)))?;

    let blinding_factor: Token<PrivateKey> =
        bincode::deserialize(blinding_factor_buf).map_err(|err| {
            JsValue::from_str(&format!("could not deserialize blinding factor {}", err))
        })?;

    POPRF::unblind_resp(&public_key, &blinding_factor, tag, &blinded_resp)
        .map_err(|err| JsValue::from_str(&format!("could not unblind response {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Service -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Evaluates the POPRF over the plaintext message and tag with the provided private key and
/// returns the evaluation.
///
/// # Throws
///
/// - If the private key fails to deserialize.
/// - If the evaluation fails.
pub fn eval(private_key_buf: &[u8], tag: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let private_key: PrivateKey = bincode::deserialize(private_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize private key {}", err)))?;

    POPRF::eval(&private_key, tag, message)
        .map_err(|err| JsValue::from_str(&format!("could not produce evaluation: {}", err)))
}

#[wasm_bindgen(js_name = blindEval)]
/// Evaluates the POPRF over the blinded message and plaintext tag with the provided private key
/// and returns the blinded response
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If the evaluation fails.
pub fn blind_eval(private_key_buf: &[u8], tag: &[u8], blinded_message_buf: &[u8]) -> Result<Vec<u8>> {
    let private_key: PrivateKey = bincode::deserialize(private_key_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize private key {}", err)))?;

    let blinded_message: POPRF::BlindMsg = bincode::deserialize(blinded_message_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize blinded response {}", err)))?;

    POPRF::blind_eval(&private_key, tag, &blinded_message)
        .map_err(|err| JsValue::from_str(&format!("could not sign message: {}", err)))
}

#[wasm_bindgen(js_name = parialEval )]
/// Evaluates the POPRF over the plaintext message and tag with the provided **share** of the
/// private key and returns the **partial** evaluation.
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If the evaluation fails.
///
/// NOTE: This method must NOT be called with a PrivateKey which is not generated via a
/// secret sharing scheme.
pub fn partial_eval(share_buf: &[u8], tag: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let share: Share<PrivateKey> = bincode::deserialize(share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not deserialize private key share {}", err))
    })?;

    POPRF::partial_eval(&share, tag, message)
        .map_err(|err| JsValue::from_str(&format!("could not produce partial evaluation: {}", err)))
}

#[wasm_bindgen(js_name = blindPartialEval)]
/// Evaluates the POPRF over the blinded message and plaintext tag with the provided **share** of
/// the private key and returns the **partial** evaluation.
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If the evaluation fails.
///
/// NOTE: This method must NOT be called with a PrivateKey which is not generated via a
/// secret sharing scheme.
pub fn blind_partial_eval(share_buf: &[u8], tag, blinded_message_buf: &[u8]) -> Result<Vec<u8>> {
    let share: Share<PrivateKey> = bincode::deserialize(share_buf).map_err(|err| {
        JsValue::from_str(&format!("could not deserialize private key share {}", err))
    })?;

    let blinded_message: POPRF::BlindMsg = bincode::deserialize(blinded_message_buf)
        .map_err(|err| JsValue::from_str(&format!("could not deserialize blinded response {}", err)))?;

    POPRF::blind_partial_eval(&share, tag, &blinded_message)
        .map_err(|err| JsValue::from_str(&format!("could not produce partial evaluation: {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Combiner -> Library
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen]
/// Aggregates a flattened vector of partial evaluations to a single threshold evaluation.
///
/// NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
/// byte vector which it will parse in chunks for each signature.
///
/// NOTE: If you are working with an array of Uint8Arrays In Javascript, the simplest
/// way to flatten them is via:
///
/// ```js
/// function flatten(arr) {
///     return Uint8Array.from(arr.reduce(function(a, b) {
///         return Array.from(a).concat(Array.from(b));
///     }, []));
/// }
/// ```
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If the aggregation fails.
pub fn aggregate(threshold: usize, evaluations_buf: &[u8]) -> Result<Vec<u8>> {
    // Break the flattened vector to and deserialize the chunks in partial evaluations.
    let evaluations: Vec<PartialResp> = evaluations_buf
        .chunks(PARTIAL_RESPONSE_LENGTH)
        .map(|buf| bincode.deserialize::<PartialResp>(buf))
        .collect()
        .map_err(|err| JsValue::from_str(&format!("could not deserialize partial responses {}", err)))?;

    POPRF::aggregate(threshold, &evaluations)
        .map_err(|err| JsValue::from_str(&format!("could not aggregate evaluations: {}", err)))
}

#[wasm_bindgen]
/// Aggregates a flattened vector of blind partial evaluations to a single blind threshold
/// evaluation.
///
/// NOTE: Wasm-bindgen does not support Vec<Vec<u8>>, so this function accepts a flattened
/// byte vector which it will parse in chunks for each signature.
///
/// NOTE: If you are working with an array of Uint8Arrays In Javascript, the simplest
/// way to flatten them is via:
///
/// ```js
/// function flatten(arr) {
///     return Uint8Array.from(arr.reduce(function(a, b) {
///         return Array.from(a).concat(Array.from(b));
///     }, []));
/// }
/// ```
///
/// # Throws
///
/// - If any of the inputs fail to deserialize.
/// - If the aggregation fails.
pub fn aggregate(threshold: usize, blinded_evaluations_buf: &[u8]) -> Result<Vec<u8>> {
    // Break the flattened vector to and deserialize the chunks in blind partial evaluations.
    let blinded_evaluations: Vec<BlindPartialResp> = blinded_evaluations_buf
        .chunks(BLIND_PARTIAL_RESPONSE_LENGTH)
        .map(|buf| bincode.deserialize::<BlindPartialResp>(buf))
        .collect()
        .map_err(|err| JsValue::from_str(&format!("could not deserialize blinded partial responses {}", err)))?;

    POPRF::blind_aggregate(threshold, &blinded_evaluations)
        .map_err(|err| JsValue::from_str(&format!("could not aggregate evaluations: {}", err)))
}

///////////////////////////////////////////////////////////////////////////
// Helpers
///////////////////////////////////////////////////////////////////////////

#[wasm_bindgen(js_name = thresholdKeygen)]
/// Generates a t-of-n polynomial and private key shares
///
/// # Safety
///
/// WARNING: This is a helper function for local testing of the library. Do not use
/// in production, unless you trust the person that generated the keys.
///
/// The seed MUST be at least 32 bytes long
pub fn threshold_keygen(n: usize, t: usize, seed: &[u8]) -> Keys {
    let mut rng = get_rng(&[seed]);
    let private = Poly::<PrivateKey>::new_from(t - 1, &mut rng);
    let shares = (0..n)
        .map(|i| private.eval(i as Index))
        .map(|e| Share {
            index: e.index,
            private: e.value,
        })
        .collect();
    let polynomial = private.commit();
    Keys {
        shares,
        polynomial,
        t,
        n,
    }
}

#[wasm_bindgen(inspectable)]
/// A blinded message along with the blinding_factor used to produce it
pub struct BlindedMessage {
    /// The resulting blinded message.
    message: POPRF::BlindMsg,
    /// The blinding_factor which was used to generate the blinded message. This will be used
    /// to unblind the signature received on the blinded message to a valid signature
    /// on the unblinded message.
    blinding_factor: Token<PrivateKey>,
}

#[wasm_bindgen]
impl BlindedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        bincode::serialize(&self.message).expect("could not serialize blinded message")
    }

    #[wasm_bindgen(getter, js_name = blindingFactor)]
    pub fn blinding_factor(&self) -> Vec<u8> {
        bincode::serialize(&self.blinding_factor).expect("could not serialize blinding factor")
    }
}

#[wasm_bindgen]
#[derive(Clone)]
/// A BLS12-377 Keypair
pub struct Keypair {
    /// The private key
    private: PrivateKey,
    /// The public key
    public: PublicKey,
}

// Need to implement custom getters if we want to return more than one value
// and expose it https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/getter-and-setter.html
#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> Vec<u8> {
        bincode::serialize(&self.private).expect("could not serialize private key")
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        bincode::serialize(&self.public).expect("could not serialize public key")
    }
}

/// Generates a single private key from the provided seed.
///
/// # Safety
///
/// The seed MUST be at least 32 bytes long
#[wasm_bindgen]
pub fn keygen(seed: &[u8]) -> Keypair {
    let mut rng = get_rng(&[seed]);
    let (private, public) = POPRF::keypair(&mut rng);
    Keypair { private, public }
}

#[wasm_bindgen]
pub struct Keys {
    shares: Vec<Share<PrivateKey>>,
    polynomial: Poly<PublicKey>,
    pub t: usize,
    pub n: usize,
}

#[wasm_bindgen]
impl Keys {
    #[wasm_bindgen(js_name = getShare)]
    pub fn get_share(&self, index: usize) -> Vec<u8> {
        bincode::serialize(&self.shares[index]).expect("could not serialize share")
    }

    #[wasm_bindgen(js_name = numShares)]
    pub fn num_shares(&self) -> usize {
        self.shares.len()
    }

    #[wasm_bindgen(getter, js_name = polynomial)]
    pub fn polynomial(&self) -> Vec<u8> {
        bincode::serialize(&self.polynomial).expect("could not serialize polynomial")
    }

    #[wasm_bindgen(getter, js_name = thresholdPublicKey)]
    pub fn threshold_public_key(&self) -> Vec<u8> {
        bincode::serialize(&self.polynomial.public_key())
            .expect("could not serialize threshold public key")
    }
}

fn get_rng(seeds: &[&[u8]]) -> impl RngCore {
    let mut outer = Blake2s256::new();
    outer.update("Celo POPRF WASM RNG Seed");
    for seed in seeds.iter() {
        outer.update(Blake2s256::digest(seed));
    }
    let seed = outer.finalize();
    ChaChaRng::from_seed(seed.into())
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_wasm() {
        threshold_wasm_should_blind(true);
        threshold_wasm_should_blind(false);
    }

    #[test]
    fn signing() {
        wasm_should_blind(true);
        wasm_should_blind(false);
    }

    fn wasm_should_blind(should_blind: bool) {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keypair = keygen(seed.to_vec());

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let (message, token) = if should_blind {
            let ret = blind(msg.clone(), &key[..]);
            (ret.message.clone(), ret.blinding_factor())
        } else {
            (msg.clone(), vec![])
        };

        let sign_fn = if should_blind {
            sign_blinded_message
        } else {
            sign
        };

        let sig = sign_fn(&keypair.private_key(), &message).unwrap();

        if should_blind {
            verify_blind_signature(&keypair.public_key(), &message, &sig).unwrap();
            let unblinded = unblind(&sig, &token).unwrap();
            verify(&keypair.public_key(), &msg, &unblinded).unwrap();
        } else {
            verify(&keypair.public_key(), &msg, &sig).unwrap();
        }
    }

    fn threshold_wasm_should_blind(should_blind: bool) {
        let (n, t) = (5, 3);
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let keys = threshold_keygen(n, t, &seed[..]);

        let msg = vec![1, 2, 3, 4, 6];
        let key = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let (message, token) = if should_blind {
            let ret = blind(msg.clone(), &key[..]);
            (ret.message.clone(), ret.blinding_factor())
        } else {
            (msg.clone(), vec![])
        };

        let sign_fn = if should_blind {
            partial_sign_blinded_message
        } else {
            partial_sign
        };

        let verify_fn = if should_blind {
            partial_verify_blind_signature
        } else {
            partial_verify
        };

        let sigs = (0..t)
            .map(|i| sign_fn(&keys.get_share(i), &message).unwrap())
            .collect::<Vec<Vec<_>>>();

        sigs.iter()
            .for_each(|sig| verify_fn(&keys.polynomial(), &message, &sig).unwrap());

        let concatenated = sigs.concat();
        let asig = combine(3, concatenated).unwrap();

        if should_blind {
            verify_blind_signature(&keys.threshold_public_key(), &message, &asig).unwrap();
            let unblinded = unblind(&asig, &token).unwrap();
            verify(&keys.threshold_public_key(), &msg, &unblinded).unwrap();
        } else {
            verify(&keys.threshold_public_key(), &msg, &asig).unwrap();
        }
    }
}
*/
