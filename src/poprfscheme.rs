use crate::api::POPRFScheme;
use crate::poprf::poprf::POPRF;
use crate::POPRFError;
use bls_crypto::hashers::{DirectHasher, Hasher};
use rand_core::RngCore;
use std::fmt::Debug;
use threshold_bls::{
    group::{Element, Scalar},
    poly::Poly,
    sig::Share,
};

const HASH_OUTPUT_BITS: usize = 256;

impl<C> POPRFScheme for C
where
    C: POPRF + Debug,
{
    type Error = POPRFError;
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
        C::verify(a.clone(), b.clone(), &z, &s_1, &s_2)?
            .then(|| ())
            .ok_or(POPRFError::VerifyError)?;
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
            .hash(&[], &serialized[..], HASH_OUTPUT_BITS)
            .map_err(|_e| POPRFError::HashingError)?;

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
        let res = C::finalize(&public.get(resp.index), &A, &B, tag, r, c, d)?;
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
            .into_iter()
            .map(|p| Share {
                private: p.private.0.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();
        let B_vec = partials
            .into_iter()
            .map(|p| Share {
                private: p.private.1.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();
        let A = C::aggregate(threshold, &A_vec)?;
        let B = C::aggregate(threshold, &B_vec)?;
        Ok((A, B))
    }

    fn eval(private: &Self::Private, tag: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let res = C::eval(&private, tag, msg)?;
        let serialized = bincode::serialize(&res)?;
        let res_hash = DirectHasher
            .hash(&[], &serialized[..], HASH_OUTPUT_BITS)
            .map_err(|_e| POPRFError::HashingError)?;

        Ok(res_hash)
    }

    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, Self::Error> {
        let res = C::eval(&private.private, tag, msg)?;
        Ok(Share {
            private: res,
            index: private.index,
        })
    }

    fn aggregate(threshold: usize, partials: &[Self::PartialResp]) -> Result<Vec<u8>, Self::Error> {
        let vec = partials
            .into_iter()
            .map(|p| Share {
                private: p.private.clone(),
                index: p.index,
            })
            .collect::<Vec<Share<C::Evaluation>>>();
        println!("partials: {:?}", &partials);
        let res = C::aggregate(threshold, &vec)?;
        println!("aggregate: {:?}", &res);
        let serialized = bincode::serialize(&res)?;
        let res_hash = DirectHasher
            .hash(&[], &serialized[..], HASH_OUTPUT_BITS)
            .map_err(|_e| POPRFError::HashingError)?;
        Ok(res_hash)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::POPRFScheme;
    use crate::poprf::Scheme;
    use crate::poprfscheme::{Poly, Share};
    use threshold_bls::curve::bls12377::PairingCurve as bls377;
    use threshold_bls::group::Element;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    type G2Scheme = crate::poprf::G2Scheme<bls377>;

    #[test]
    fn blind_and_unblind() {
        let mut rng = rand::thread_rng();
        let (private, public) = G2Scheme::keypair(&mut rng);
        let msg = "Hello World!";
        let tag = "Bob";
        let (token, blindmsg) = G2Scheme::blind_msg(msg.as_bytes(), &mut rng).unwrap();
        let blind_resp = G2Scheme::blind_eval(&private, tag.as_bytes(), &blindmsg).unwrap();
        let unblind_result =
            G2Scheme::unblind_resp(&public, &token, &tag.as_bytes(), &blind_resp).unwrap();
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
        let _result =
            G2Scheme::unblind_resp(&public, &token, &tag.as_bytes(), &blind_resp).unwrap();
    }

    #[test]
    fn aggregate() {
        let mut rng = rand::thread_rng();
        let t: usize = 3;
        let msg = "Hello World!";
        let tag = "Bob";
        let mut partial_resps = Vec::<<G2Scheme as POPRFScheme>::PartialResp>::new();
        let private = Poly::<<G2Scheme as Scheme>::Private>::new_from(t - 1, &mut rng);
        for i in 0..t {
            let key = private.eval(i.try_into().unwrap());
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: key.value,
                index: i.try_into().unwrap(),
            };
            let partial_resp =
                G2Scheme::partial_eval(&partial_key, tag.as_bytes(), msg.as_bytes()).unwrap();
            partial_resps.push(partial_resp);
        }
        let agg_result = G2Scheme::aggregate(t, &partial_resps[..]).unwrap();
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
        let mut partial_resps = Vec::<<G2Scheme as POPRFScheme>::PartialResp>::new();
        for i in 0..t - 1 {
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
            private: private.get(index),
            index: index,
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
            private: private,
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
    fn eval() {
        //let mut rng = rand::thread_rng();
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let msg = "Hello World!";
        let tag = "Bob";
        let (private, _) = G2Scheme::keypair(&mut rng);
        let result = G2Scheme::eval(&private, tag.as_bytes(), msg.as_bytes()).unwrap();
        let expected_result = [242, 161, 166, 74, 193, 182, 33, 175, 45, 252, 166, 159, 197, 107, 174, 129, 237, 135, 253, 195, 59, 54, 121, 130, 157, 229, 160, 87, 177, 112, 41, 187, 200, 89, 96, 168, 101, 179, 108, 66, 16, 209, 179, 133, 19, 187, 249, 209, 167, 112, 237, 33, 139, 98, 122, 30, 224, 228, 37, 140, 55, 178, 26, 0, 156, 132, 86, 109, 41, 50, 143, 180, 111, 209, 41, 145, 36, 11, 150, 67, 190, 198, 134, 81, 23, 237, 255, 184, 143, 170, 189, 115, 247, 207, 163, 162, 110, 56, 149, 238, 31, 155, 173, 56, 165, 2, 190, 73, 158, 223, 13, 239, 2, 28, 62, 59, 37, 26, 98, 13, 105, 163, 15, 56, 93, 24, 182, 210, 143, 82, 135, 193, 108, 64, 163, 88, 225, 7, 23, 144, 87, 145, 175, 24, 160, 252, 199, 125, 74, 83, 11, 21, 99, 105, 139, 134, 252, 47, 189, 28, 187, 13, 24, 88, 251, 161, 215, 39, 202, 55, 42, 208, 35, 15, 208, 248, 232, 166, 7, 220, 147, 74, 165, 201, 29, 136, 56, 27, 191, 81, 150, 202, 24, 102, 25, 231, 84, 229, 28, 77, 138, 97, 135, 182, 202, 103, 71, 18, 61, 244, 202, 154, 219, 255, 249, 107, 183, 73, 26, 200, 170, 172, 5, 152, 3, 4, 38, 187, 79, 94, 118, 222, 206, 23, 181, 143, 5, 55, 27, 41, 244, 15, 81, 35, 21, 192, 175, 122, 161, 98, 24, 228, 29, 54, 182, 89];
        assert_eq!(result, expected_result);
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
        let mut partial_resps = Vec::<<G2Scheme as POPRFScheme>::BlindPartialResp>::new();
        for i in 0..t {
            let partial_key: Share<<G2Scheme as Scheme>::Private> = Share {
                private: private.eval(i.try_into().unwrap()).value,
                index: i.try_into().unwrap(),
            };
            let partial_resp =
                G2Scheme::blind_partial_eval(&partial_key, tag.as_bytes(), &blindmsg).unwrap();
            partial_resps.push(partial_resp);
        }
        let blind_resp = G2Scheme::blind_aggregate(t, &partial_resps[..]).unwrap();
        let agg_result =
            G2Scheme::unblind_resp(&public_key, &token, tag.as_bytes(), &blind_resp).unwrap();
        let agg_key = private.get(0);
        let result = G2Scheme::eval(&agg_key, tag.as_bytes(), msg.as_bytes()).unwrap();

        assert_eq!(&agg_result, &result);
    }
}
