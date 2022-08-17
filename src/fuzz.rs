use bls_crypto::hashers::DirectHasher;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use threshold_bls::curve::bls12377::PairingCurve as bls377;
use threshold_bls::group::Element;

use crate::api::{Poly, PoprfScheme, PrfScheme, Scheme, Share, ThresholdScheme};
use crate::bls12_377::Scalar;
use crate::hash_to_field::{HashToField, TryAndIncrement};
//use crate::PoprfError;

type G2Scheme = crate::poprf::G2Scheme<bls377>;

pub fn hash_to_field(data: &[u8]) {
    let domain = b"H2FFUZZ";
    let hasher = TryAndIncrement::<_, Scalar>::new(&DirectHasher);
    let hash = hasher.hash_to_field(domain, data).unwrap();
    assert!(hash != Scalar::one());
    assert!(hash != Scalar::zero());
}

// This struct exists to make it easy for the fuzzer to know what sort of
// inputs to provide. We allow the fuzzer to seed the RNG, which is
// deterministic anyway (we only seed it to avoid code changes),
// and supply the message and tag.
#[derive(arbitrary::Arbitrary, Debug)]
pub struct PoprfFuzzInput {
    msg: Vec<u8>,
    tag: Vec<u8>,
    seed: [u8; 32],
    terms: u8,
}

pub fn poprfscheme(input: PoprfFuzzInput) {
    //let mut rng = rand::thread_rng();
    let mut rng = ChaCha8Rng::from_seed(input.seed);

    let t: usize = (input.terms % 27) as usize + 3;
    let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
    let public = private.commit::<<G2Scheme as Scheme>::Public>();
    let public_key = public.public_key();
    let (token, blindmsg) = G2Scheme::blind_msg(&input.msg, &mut rng).unwrap();
    let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::BlindPartialResp>::new();

    for i in 1..t + 1 {
        let eval = private.eval(i.try_into().unwrap());
        let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
            private: eval.value,
            index: eval.index,
        };
        let partial_resp =
            G2Scheme::blind_partial_eval(&partial_key, &input.tag, &blindmsg).unwrap();
        partial_resps.push(partial_resp);
    }

    let blind_resp = G2Scheme::blind_aggregate(t, &partial_resps[..]).unwrap();
    let agg_result = G2Scheme::unblind_resp(public_key, &token, &input.tag, &blind_resp).unwrap();

    // Poly.get(0) returns the constant term, which is the aggregated private key.
    let agg_key = private.get(0);
    let result = G2Scheme::eval(&agg_key, &input.tag, &input.msg).unwrap();
    assert_eq!(agg_result, result);
}

// This struct exists to make it easy for the fuzzer to know what sort of
// inputs to provide. We allow the fuzzer to seed the RNG, which is
// deterministic anyway (we only seed it to avoid code changes),
// and supply the message and tag.
#[derive(arbitrary::Arbitrary, Debug)]
pub struct PartialUnblindFuzzInput {
    msg: Vec<u8>,
    tag: Vec<u8>,
    seed: [u8; 32],
    terms: u8,
    index: u8,
}

pub fn partialunblind(input: PartialUnblindFuzzInput) {
    //let mut rng = rand::thread_rng();

    let mut rng = ChaCha8Rng::from_seed(input.seed);

    let t: usize = (input.terms % 27) as usize + 3;
    let index: u32 = input.index as u32 % t as u32;
    let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
    let public = private.commit::<<G2Scheme as Scheme>::Public>();
    let (token, blindmsg) = G2Scheme::blind_msg(&input.msg, &mut rng).unwrap();
    let private_key = Share {
        private: private.eval(index).value,
        index,
    };
    let blind_partial_resp =
        G2Scheme::blind_partial_eval(&private_key, &input.tag, &blindmsg).unwrap();
    let blind_result =
        G2Scheme::unblind_partial_resp(&public, &token, &input.tag, &blind_partial_resp).unwrap();
    let result = G2Scheme::partial_eval(&private_key, &input.tag, &input.msg).unwrap();
    assert_eq!(&blind_result, &result);
}
