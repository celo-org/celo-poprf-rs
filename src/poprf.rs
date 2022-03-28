//use ark_ec::hashing::field_hashers::DefaultFieldHasher;
//use rand::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, marker::PhantomData};
use threshold_bls::{
    group::{Element, PairingCurve, Point, Scalar},
    poly::{Eval, Poly},
    sig::Share,
};
use crate::POPRFError;

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
    type Evaluation: Element<RHS = Self::Private> + Serialize + DeserializeOwned;

    // Returns a new fresh keypair usable by the scheme.
    /*fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);

        let mut public = Self::Public::one();
        public.mul(&private);

        (private, public)
    }*/
}

pub mod poprf {
use super::*;
    pub trait POPRFInterface : Scheme {
        fn req(
            msg: &[u8],
        ) -> Result<
            (
                Self::Private,
                Self::Private,
                Self::Private,
                Self::Public,
                Self::Public,
            ),
            POPRFError,
        > {
            let rng = &mut rand::thread_rng();
            let r = Self::Private::rand(rng); // TODO: move to preprocessing?
            let c = Self::Private::rand(rng);
            let d = Self::Private::rand(rng);

            let mut h = Self::Public::one();
            h.map(msg).map_err(|_| POPRFError::HashingError)?;

            let mut a = h.clone();
            a.mul(&r); // a = h^r

            h.mul(&c);
            let mut g2 = Self::Public::one();
            let mut b = h.clone();
            g2.mul(&d);
            b.add(&g2); // b = h^c * g2^d

            Ok((r, c, d, a, b))
        }

        // Prove(a, b, c/r, d)
        fn prove(
            a: &mut Self::Public,//&mut Self::G2,
            b: &Self::Public,//&Self::G2,
            x: &mut Self::Private,//&mut Self::Scalar,
            y: &mut Self::Private,//&mut Self::Scalar,
        ) -> Result<(Self::Private, Self::Private, Self::Private), POPRFError> {
            let rng = &mut rand::thread_rng();
            let v1 = Self::Private::rand(rng);
            let v2 = Self::Private::rand(rng);

            // v = g2^v1 * a^v2
            let mut g2 = Self::Public::one();
            g2.mul(&v1);
            a.mul(&v2);
            let mut v = g2.clone();
            v.add(&a);

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&g2)?;
            let v_ser = bincode::serialize(&v)?;
            let a_ser = bincode::serialize(&a)?;
            let b_ser = bincode::serialize(&b)?;
            let mut concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            // TODO: implement hash to scalar field
            let mut z = Self::Private::new();
            //z.map(&concatenate)?;

            // s1 = v1 - y * z
            let mut s1 = v1;
            y.mul(&z);
            s1.sub(&y);

            // s2 = v2 - x * z
            let mut s2 = v2;
            x.mul(&z);
            s2.sub(&x);

            Ok((z, s1, s2))
        }

        fn verify(
            a: &mut Self::Public,//&mut Self::G2,
            b: &mut Self::Public,//&mut Self::G2,
            z: &Self::Private,//&Self::Scalar,
            s1: &Self::Private,//&Self::Scalar,
            s2: &Self::Private,//&Self::Scalar,
        ) -> Result<bool, POPRFError> {
            // v = g2^s1 * a^s2 * b^z
            let mut g2 = Self::Public::one();
            g2.mul(&s1);
            a.mul(&s2);
            b.mul(&z);
            let mut v = g2.clone();
            v.add(&a);
            v.add(&b);

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&g2)?;
            let v_ser = bincode::serialize(&v)?;
            let a_ser = bincode::serialize(&a)?;
            let b_ser = bincode::serialize(&b)?;
            let mut concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            // TODO: implement hash to scalar field
            let h = Self::Private::new();

            Ok(*z == h)
        }

        fn blind_ev(
            k: &Self::Private,
            t: &[u8],
            a: &Self::Public,
            b: &Self::Public,
        ) -> Result<(Self::Evaluation, Self::Evaluation), POPRFError>;

        // TODO: Separate out aggregate into its own trait
        #[allow(non_snake_case)]
        fn aggregate(
            threshold: usize,
            shares: &[Share<(Self::Evaluation, Self::Evaluation)>],
        ) -> Result<(Self::Evaluation, Self::Evaluation), POPRFError> {
            if threshold > shares.len() {
                return Err(POPRFError::NotEnoughResponses(shares.len(), threshold));
            }

            let A_valid_shares: Vec<Eval<Self::Evaluation>> = shares
                .iter()
                .map(|share| {
                    Ok(Eval {
                        index: share.index,
                        value: share.private.0.clone(),
                    })
                })
                .collect::<Result<_, POPRFError>>()?;
            let A = Poly::recover(threshold, A_valid_shares)?;

            let B_valid_shares: Vec<Eval<Self::Evaluation>> = shares
                .iter()
                .map(|share| {
                    Ok(Eval {
                        index: share.index,
                        value: share.private.1.clone(),
                    })
                })
                .collect::<Result<_, POPRFError>>()?;
            let B = Poly::recover(threshold, B_valid_shares)?;

            Ok((A, B))
        }

        #[allow(non_snake_case)]
        fn finalize(
            v: &Self::Public,
            A: &Self::Evaluation,
            B: &Self::Evaluation,
            t: &[u8],
            r: &Self::Private,
            c: &Self::Private,
            d: &Self::Private,
        ) -> Result<Self::Evaluation, POPRFError>;
    }
}

// G2Interface implements pairings with public keys over G2
#[derive(Clone, Debug)]
pub struct G2Interface<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C: PairingCurve> Scheme for G2Interface<C>
{
    type Private = C::Scalar; 
    type Public = C::G2; 
    type Evaluation = C::GT; 
}

impl<C> poprf::POPRFInterface for G2Interface<C>
where
    C: PairingCurve,
{
    #[allow(non_snake_case)]
    fn blind_ev(
        k: &Self::Private,
        t: &[u8],
        a: &Self::Public,
        b: &Self::Public,
    ) -> Result<(Self::Evaluation, Self::Evaluation), POPRFError> {
        let mut h = C::G1::new();
        h.map(t).map_err(|_| POPRFError::HashingError)?;
        h.mul(k);
        // A <- e(H1(t)^k, a)
        let A = C::pair(&h, a);
        // B <- e(H1(t)^k, b)
        let B = C::pair(&h, b);

        Ok((A, B)) // rep <- (A, B)
    }

    #[allow(non_snake_case)]
    fn finalize(
        v: &Self::Public,
        A: &Self::Evaluation,
        B: &Self::Evaluation,
        t: &[u8],
        r: &Self::Private,
        c: &Self::Private,
        d: &Self::Private,
    ) -> Result<Self::Evaluation, POPRFError> {
        // y_A = A^(r^(-1))
        let r_inv = r.inverse().ok_or(POPRFError::NoInverse)?;
        let mut y_A = A.clone();
        y_A.mul(&r_inv); 

        let mut h = C::G1::new();
        h.map(t).map_err(|_| POPRFError::HashingError)?;
        // y_B <- B^(c^(-1)) e(H1(t), v^(-dc^(-1)))
        let c_inv = c.inverse().ok_or(POPRFError::NoInverse)?;
        let mut vdc = v.clone();
        let mut dc = d.clone();
        dc.mul(&c_inv);
        dc.negate();
        vdc.mul(&dc);

        let mut y_B = B.clone();
        y_B.mul(&c_inv);
        y_B.add(&C::pair(&h, &vdc));
        assert_eq!(y_A, y_B);

        Ok(y_A)
    }
}
