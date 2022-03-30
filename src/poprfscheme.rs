use rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, fmt::Debug};
use threshold_bls::{
    group::{Element, Scalar},
    poly::Poly,
    sig::Share,
};
use crate::poprf::poprf::POPRF;
use crate::api::POPRFScheme;
use crate::POPRFError;
use crate::poprf::Scheme;

impl<C> POPRFScheme for C
where
    C : POPRF + Debug,
{
    type Error = POPRFError;
    type Token = (C::Private, C::Private, C::Private);
    type Proof = (C::Private, C::Private, C::Private);
    type BlindMsg = (Self::Proof, C::Public, C::Public);
    type BlindResp = (C::Evaluation, C::Evaluation);
    type Resp = C::Evaluation;
    type PartialResp = Share<Self::Resp>;
    type BlindPartialResp = Share<Self::BlindResp>;

    fn blind_msg<R: RngCore>(msg: &[u8], rng: &mut R) -> Result<(Self::Token, Self::BlindMsg), Self::Error> {
        let (r,c,d,a,b) = C::req(msg, rng).unwrap();
        let mut c_div_r = c.clone();
        let r_inv = r.inverse().ok_or(Self::Error::NoInverse).unwrap();
        c_div_r.mul(&r_inv);
        let (z,s_1,s_2) = C::prove(&mut a.clone(),&b,&mut c_div_r.clone(),&mut d.clone(), rng).unwrap();
        let token = (r,c,d);
        let proof = (z,s_1,s_2);
        let blmsg = (proof,a,b);
        Ok((token, blmsg))
    }

    #[allow(non_snake_case)]
    fn blind_eval(
        private: &Self::Private,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindResp, Self::Error> {
        let (pi,a,b) = msg;
        let (z,s_1,s_2) = pi;
        C::verify(&mut a.clone(), &mut b.clone(), &z, &s_1, &s_2)?.then(|| ()).ok_or(POPRFError::VerifyError)?;
        let (A,B) = C::blind_ev(private, tag, a, b)?;
        Ok((A,B))
    }

    #[allow(non_snake_case)]
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

    fn blind_partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &Self::BlindMsg,
    ) -> Result<Self::BlindPartialResp, Self::Error> {
        let resp = Self::blind_eval(&private.private, tag, msg)?;
        Ok(Share{ index: private.index, private: resp })
    }

    #[allow(non_snake_case)]
    fn unblind_partial_resp(
        public: &Poly<Self::Public>,
        token: &Self::Token,
        tag: &[u8],
        resp: &Self::BlindPartialResp,
    ) -> Result<Self::PartialResp, Self::Error> {
        let (r,c,d) = token;
        let (A,B) = resp.private.clone();
        let res = C::finalize(&public.get(resp.index), &A, &B, tag, r, c, d)?;
        Ok(Share { private: res, index: resp.index })
    }

    #[allow(non_snake_case)]
    fn blind_aggregate(
        threshold: usize,
        partials: &[Self::BlindPartialResp],
    ) -> Result<Self::BlindResp, Self::Error> {
        let A_vec = partials.into_iter().map(|p|  Share { private: p.private.0.clone(), index: p.index }).collect::<Vec<Share<C::Evaluation>>>();
        let B_vec = partials.into_iter().map(|p|  Share { private: p.private.1.clone(), index: p.index }).collect::<Vec<Share<C::Evaluation>>>();
        let A = C::aggregate(threshold, &A_vec)?;
        let B = C::aggregate(threshold, &B_vec)?;
        Ok((A,B))
    }

    fn partial_eval(
        private: &Share<Self::Private>,
        tag: &[u8],
        msg: &[u8],
    ) -> Result<Self::PartialResp, Self::Error> {
        let res = C::eval(&private.private, tag, msg)?;
        Ok(Share { private: res, index: private.index })
    }

    fn aggregate(threshold: usize, partials: &[Self::PartialResp]) -> Result<Vec<u8>, Self::Error> {
        let vec = partials.into_iter().map(|p|  Share { private: p.private.clone(), index: p.index }).collect::<Vec<Share<C::Evaluation>>>();
        let res = C::aggregate(threshold, &vec)?;
        // TODO: Hash output
        Ok(Vec::<u8>::new())
    }
}
