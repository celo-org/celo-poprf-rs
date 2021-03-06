use crate::api::{PoprfScheme, PrfScheme, ThresholdScheme};
use crate::poprf::Poprf;
use crate::PoprfError;
use bls_crypto::hashers::{DirectHasher, Hasher};
use rand_core::RngCore;
use std::fmt::Debug;
use threshold_bls::{
    group::{Element, Scalar},
    poly::Poly,
    sig::Share,
};

/// 8-byte constant hashing domain for the evaluation result hashing.
const NIZK_HASH_DOMAIN: &[u8] = b"PRFEVALH";
const HASH_OUTPUT_BYTES: usize = 32;

impl<C> PrfScheme for C
where
    C: Poprf + Debug,
{
    type Error = PoprfError;

    fn eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, <Self as PrfScheme>::Error> {
        let res = C::eval(private, tag, msg)?;
        let serialized = bincode::serialize(&res)?;
        let res_hash = DirectHasher
            .hash(NIZK_HASH_DOMAIN, &serialized[..], HASH_OUTPUT_BYTES)
            .map_err(|_e| PoprfError::HashingError)?;

        Ok(res_hash)
    }
}

impl<C> ThresholdScheme for C
where
    C: Poprf + Debug,
{
    type Error = PoprfError;
    type PartialResp = Share<C::Evaluation>;

    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, <Self as ThresholdScheme>::Error> {
        let res = C::eval(&private.private, tag, msg)?;
        Ok(Share {
            private: res,
            index: private.index,
        })
    }

    fn aggregate(
        threshold: usize,
        partials: &[Self::PartialResp],
    ) -> Result<Vec<u8>, <Self as ThresholdScheme>::Error> {
        let vec = partials
            .iter()
            .map(|p| Share {
                private: p.private.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();
        let res = C::aggregate(threshold, &vec)?;
        let serialized = bincode::serialize(&res)?;
        let res_hash = DirectHasher
            .hash(NIZK_HASH_DOMAIN, &serialized[..], HASH_OUTPUT_BYTES)
            .map_err(|_e| PoprfError::HashingError)?;
        Ok(res_hash)
    }
}

impl<C> PoprfScheme for C
where
    C: Poprf + Debug,
{
    type Error = PoprfError;
    type Token = (C::Private, C::Private, C::Private);
    type BlindMsg = (C::Private, C::Private, C::Private, C::Public, C::Public);
    type BlindResp = (C::Evaluation, C::Evaluation);
    type PartialResp = Share<C::Evaluation>;
    type BlindPartialResp = Share<Self::BlindResp>;

    fn blind_msg<R: RngCore>(
        msg: &[u8],
        rng: &mut R,
    ) -> Result<(Self::Token, Self::BlindMsg), Self::Error> {
        let (r, c, d, a, b) = C::req(msg, rng).unwrap();
        let mut c_div_r = c.clone();
        let r_inv = r.inverse().ok_or(Self::Error::NoInverse).unwrap();
        c_div_r.mul(&r_inv);
        let (z, s_1, s_2) = C::prove(a.clone(), &b, c_div_r.clone(), d.clone(), rng).unwrap();
        let token = (r, c, d);
        let blmsg = (z, s_1, s_2, a, b);
        Ok((token, blmsg))
    }

    #[allow(non_snake_case)]
    fn blind_eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindResp, Self::Error> {
        let (z, s_1, s_2, a, b) = msg;
        C::verify(a.clone(), b.clone(), z, s_1, s_2)?
            .then(|| ())
            .ok_or(PoprfError::VerifyError)?;
        let (A, B) = C::blind_ev(private, tag, a, b)?;
        Ok((A, B))
    }

    #[allow(non_snake_case)]
    fn unblind_resp(
        public: &Self::Public,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindResp,
    ) -> Result<Vec<u8>, Self::Error> {
        let (r, c, d) = token;
        let (A, B) = resp;
        let res = C::finalize(public, A, B, tag, r, c, d)?;
        let serialized = bincode::serialize(&res)?;
        let res_hash = DirectHasher
            .hash(NIZK_HASH_DOMAIN, &serialized[..], HASH_OUTPUT_BYTES)
            .map_err(|_e| PoprfError::HashingError)?;

        Ok(res_hash)
    }

    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, Self::Error> {
        let resp = Self::blind_eval(&private.private, tag, msg)?;
        Ok(Share {
            index: private.index,
            private: resp,
        })
    }

    #[allow(non_snake_case)]
    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, Self::Error> {
        let (r, c, d) = token;
        let (A, B) = resp.private.clone();
        let res = C::finalize(&public.eval(resp.index).value, &A, &B, tag, r, c, d)?;
        Ok(Share {
            private: res,
            index: resp.index,
        })
    }

    #[allow(non_snake_case)]
    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, Self::Error> {
        let A_vec = partials
            .iter()
            .map(|p| Share {
                private: p.private.0.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();
        let B_vec = partials
            .iter()
            .map(|p| Share {
                private: p.private.1.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();

        let A = C::aggregate(threshold, &A_vec)?;
        let B = C::aggregate(threshold, &B_vec)?;
        Ok((A, B))
    }
}

#[cfg(test)]
mod tests {
    use crate::api::{PoprfScheme, PrfScheme, Scheme, ThresholdScheme};
    use crate::poprfscheme::{Poly, Share};
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use threshold_bls::curve::bls12377::PairingCurve as bls377;
    use threshold_bls::group::Element;

    type G2Scheme = crate::poprf::G2Scheme<bls377>;

    #[test]
    fn eval() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let msg = "Hello World!";
        let tag = "Bob";
        let (private, _) = G2Scheme::keypair(&mut rng);
        let result = G2Scheme::eval(&private, tag.as_bytes(), msg.as_bytes()).unwrap();
        let expected_result = [
            151, 205, 148, 96, 202, 50, 200, 245, 255, 47, 156, 23, 121, 48, 42, 74, 231, 208, 239,
            211, 82, 232, 45, 2, 181, 83, 52, 224, 54, 232, 143, 114,
        ];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn blind_and_unblind() {
        let mut rng = rand::thread_rng();
        let (private, public) = G2Scheme::keypair(&mut rng);
        let msg = "Hello World!";
        let tag = "Bob";
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let blind_resp = G2Scheme::blind_eval(&private, tag.as_bytes(), &blindmsg).unwrap();
        let unblind_result =
            G2Scheme::unblind_resp(&public, &token, tag.as_bytes(), &blind_resp).unwrap();
        let result = G2Scheme::eval(&private, tag.as_bytes(), msg.as_bytes()).unwrap();
        assert_eq!(&unblind_result, &result);
    }

    #[test]
    #[should_panic]
    fn blind_and_unblind_wrong_key() {
        let mut rng = rand::thread_rng();
        let (mut private, public) = G2Scheme::keypair(&mut rng);
        let elem = <G2Scheme as Scheme>::Private::rand(&mut rng);
        private.mul(&elem);
        let msg = "Hello World!";
        let tag = "Bob";
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let blind_resp = G2Scheme::blind_eval(&private, tag.as_bytes(), &blindmsg).unwrap();
        let _result = G2Scheme::unblind_resp(&public, &token, tag.as_bytes(), &blind_resp).unwrap();
    }

    #[test]
    fn aggregate() {
        let mut rng = rand::thread_rng();
        let t: usize = 3;
        let msg = "Hello World!";
        let tag = "Bob";
        let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::PartialResp>::new();
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        for i in 1..t + 1 {
            let key = private.eval(i.try_into().unwrap());
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: key.value,
                index: key.index,
            };
            let partial_resp =
                G2Scheme::partial_eval(&partial_key, tag.as_bytes(), msg.as_bytes()).unwrap();
            partial_resps.push(partial_resp);
        }
        let agg_result = G2Scheme::aggregate(t, &partial_resps[..]).unwrap();

        // Poly.get(0) returns the constant term, which is the aggregated private key.
        let agg_key = private.get(0);
        let result = G2Scheme::eval(&agg_key, tag.as_bytes(), msg.as_bytes()).unwrap();

        assert_eq!(&agg_result, &result);
    }

    #[test]
    #[should_panic]
    fn aggregate_not_enough_shares() {
        let mut rng = rand::thread_rng();
        let t: usize = 5;
        let msg = "Hello World!";
        let tag = "Bob";
        let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::PartialResp>::new();
        for i in 1..t {
            let (key, _) = G2Scheme::keypair(&mut rng);
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: key,
                index: i.try_into().unwrap(),
            };
            let partial_resp =
                G2Scheme::partial_eval(&partial_key, tag.as_bytes(), msg.as_bytes()).unwrap();
            partial_resps.push(partial_resp);
        }
        let _result = G2Scheme::aggregate(t, &partial_resps[..]).unwrap();
    }

    #[test]
    fn unblind_partial() {
        let mut rng = rand::thread_rng();
        let msg = "Hello World!";
        let tag = "Bob";
        let t = 5;
        let index = 1;
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        let public = private.commit::<<G2Scheme as Scheme>::Public>();
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let private_key = Share {
            private: private.eval(index).value,
            index,
        };
        let blind_partial_resp =
            G2Scheme::blind_partial_eval(&private_key, tag.as_bytes(), &blindmsg).unwrap();
        let blind_result =
            G2Scheme::unblind_partial_resp(&public, &token, tag.as_bytes(), &blind_partial_resp)
                .unwrap();
        let result = G2Scheme::partial_eval(&private_key, tag.as_bytes(), msg.as_bytes()).unwrap();
        assert_eq!(&blind_result, &result);
    }

    #[test]
    #[should_panic]
    fn unblind_partial_wrong_key() {
        let mut rng = rand::thread_rng();
        let msg = "Hello World!";
        let tag = "Bob";
        let t = 5;
        let idx = 1;
        let (private, _) = G2Scheme::keypair(&mut rng);
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let partial_key = Share {
            private,
            index: idx,
        };
        let blind_partial_resp =
            G2Scheme::blind_partial_eval(&partial_key, tag.as_bytes(), &blindmsg).unwrap();
        let public_poly = Poly::<<G2Scheme as Scheme>::Public>::new_from(t - 1, &mut rng);
        let _result = G2Scheme::unblind_partial_resp(
            &public_poly,
            &token,
            tag.as_bytes(),
            &blind_partial_resp,
        )
        .unwrap();
    }

    #[test]
    fn dist_poprf() {
        let mut rng = rand::thread_rng();
        let msg = "Hello World!";
        let tag = "Bob";
        let t = 5;
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        let public = private.commit::<<G2Scheme as Scheme>::Public>();
        let public_key = public.public_key();
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::BlindPartialResp>::new();
        for i in 1..t + 1 {
            let eval = private.eval(i.try_into().unwrap());
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: eval.value,
                index: eval.index,
            };
            let partial_resp =
                G2Scheme::blind_partial_eval(&partial_key, tag.as_bytes(), &blindmsg).unwrap();
            partial_resps.push(partial_resp);
        }
        let blind_resp = G2Scheme::blind_aggregate(t, &partial_resps[..]).unwrap();
        let agg_result =
            G2Scheme::unblind_resp(public_key, &token, tag.as_bytes(), &blind_resp).unwrap();

        // Poly.get(0) returns the constant term, which is the aggregated private key.
        let agg_key = private.get(0);
        let result = G2Scheme::eval(&agg_key, tag.as_bytes(), msg.as_bytes()).unwrap();
        assert_eq!(&agg_result, &result);
    }

    #[test]
    #[should_panic]
    fn blind_agg_not_enough_shares() {
        let mut rng = rand::thread_rng();
        let msg = "Hello World!";
        let tag = "Bob";
        let t = 5;
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        let (_token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::BlindPartialResp>::new();
        for i in 1..t {
            let eval = private.eval(i.try_into().unwrap());
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: eval.value,
                index: eval.index,
            };
            let partial_resp =
                G2Scheme::blind_partial_eval(&partial_key, tag.as_bytes(), &blindmsg).unwrap();
            partial_resps.push(partial_resp);
        }

        // Should panic due to unwrap on error due to not enough shares.
        let _blind_resp = G2Scheme::blind_aggregate(t, &partial_resps[..]).unwrap();
    }

    #[test]
    #[should_panic]
    fn dist_poprf_wrong_keys() {
        let mut rng = rand::thread_rng();
        let msg = "Hello World!";
        let tag = "Bob";
        let t = 5;
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        let private_wrong = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        let public = private.commit::<<G2Scheme as Scheme>::Public>();
        let public_key = public.public_key();
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let mut partial_resps = Vec::<<G2Scheme as PoprfScheme>::BlindPartialResp>::new();
        for i in 1..t + 1 {
            let eval = private_wrong.eval(i.try_into().unwrap());
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: eval.value,
                index: eval.index,
            };
            let partial_resp =
                G2Scheme::blind_partial_eval(&partial_key, tag.as_bytes(), &blindmsg).unwrap();
            partial_resps.push(partial_resp);
        }
        let blind_resp = G2Scheme::blind_aggregate(t, &partial_resps[..]).unwrap();

        // Should panic due to unwrap on verifiation error.
        let _agg_result =
            G2Scheme::unblind_resp(public_key, &token, tag.as_bytes(), &blind_resp).unwrap();
    }
}
