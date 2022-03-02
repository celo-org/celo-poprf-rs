use rand::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;
use threshold_bls::{
    group::{Element, PairingCurve, Point, Scalar},
    sig::{Share},
};

#[derive(Debug, Error)]
pub enum POPRFError {
    #[error("could not hash to curve")]
    HashingError,

    #[error("could not serialize")]
    SerializationError,

    #[error("not enough responses: {0}/{1}")]
    NotEnoughResponses(usize, usize),

    #[error("could not inverse")]
    NoInverse,
}

pub mod poprf {
    use super::*;

    pub trait POPRFScheme {
        type Scalar: Scalar<RHS = Self::Scalar>;

        type G1: Point<RHS = Self::Scalar> + Serialize + DeserializeOwned;

        type G2: Point<RHS = Self::Scalar> + Serialize + DeserializeOwned;

        type GT: Element;

        fn req(
            v: &Self::G2, // remove?
            t: &[u8],     // non-secret domain tag
            msg: &[u8],
        ) -> Result<
            (
                Vec<u8>,
                Vec<u8>,
                Self::Scalar,
                Self::Scalar,
                Self::Scalar,
                Self::G2,
                Self::G2,
            ),
            POPRFError,
        > {
            let rng = &mut rand::thread_rng();
            let r = Self::Scalar::rand(rng); // TODO: move to preprocessing?
            let c = Self::Scalar::rand(rng);
            let d = Self::Scalar::rand(rng);

            let mut h = Self::G2::one();
            h.map(msg).map_err(|_| POPRFError::HashingError)?;

            let a = h.mul(&r);
            // TODO: building error
            let b = h.mul(&c).add(&Self::G2::one().mul(&d)); // b = h^c * g2^d

            Ok((t.into(), msg.into(), r, c, d, a, b))
        }

        // Prove(a, b, c/r, d)
        fn prove(
            a: &Self::G2,
            b: &Self::G2,
            x: &Self::Scalar,
            y: &Self::Scalar,
        ) -> Result<(Self::Scalar, Self::Scalar, Self::Scalar), POPRFError> {
            let rng = &mut rand::thread_rng();
            let v1 = Self::Scalar::rand(rng);
            let v2 = Self::Scalar::rand(rng);
            let mut g2 = Self::G2::one();
            let v = g2.mul(&v1).add(a.clone().mul(&v2)); // ERROR: method not found in `()`

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&g2).map_err(|_| POPRFError::SerializationError)?;
            let v_ser = bincode::serialize(&v).map_err(|_| POPRFError::SerializationError)?;
            let a_ser = bincode::serialize(&a).map_err(|_| POPRFError::SerializationError)?;
            let b_ser = bincode::serialize(&b).map_err(|_| POPRFError::SerializationError)?;
            let mut concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            // TODO: implement hash to scalar field
            let mut z = Self::G2::new();
            z.map(&concatenate).map_err(|_| POPRFError::HashingError)?;

            let s1 = v1.sub(y.clone().mul(&z));
            let s2 = v2.sub(x.clone().mul(&z));

            Ok((z, s1, s2))
        }
    //
        fn verify(
            a: &Self::G2,
            b: &Self::G2,
            z: &Self::Scalar,
            s1: &Self::Scalar,
            s2: &Self::Scalar,
        ) -> Result<bool, POPRFError> {
            let g2 = Self::G2::one();
            let v = g2.mul(&s1).add(a.clone().mul(&s2)).add(b.clone().mul(&z));

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&g2).map_err(|_| POPRFError::SerializationError)?;
            let v_ser = bincode::serialize(&v).map_err(|_| POPRFError::SerializationError)?;
            let a_ser = bincode::serialize(&a).map_err(|_| POPRFError::SerializationError)?;
            let b_ser = bincode::serialize(&b).map_err(|_| POPRFError::SerializationError)?;
            let mut concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            // TODO: implement hash to scalar field
            let h;

            Ok(z == h)
        }

        fn blind_ev(
            k: Self::Scalar,
            t: &[u8],
            a: Self::G2,
            b: Self::G2,
        ) -> Result<(Self::GT, Self::GT), POPRFError>;

        fn aggregate(
            threshold: usize,
            shares: &[(Share<Self::GT>, Share<Self::GT>)],
        ) -> Result<(Self::GT, Self::GT), POPRFError> {
            if threshold > shares.len() {
                return Err(POPRFError::NotEnoughResponses(
                    shares.len(),
                    threshold,
                ));
            }

            let mut A = Self::GT::new();
            let mut B = Self::GT::new();
            shares.iter().map(|(Ai, Bi)| {
                let lambda; // TODO: lambda_i(0)
                A.add(Ai.mul(&lambda));
                B.add(Bi.mul(&lambda));
            });

            Ok((A, B))
        }

        fn finalize(
            v: &Self::G2,
            A: &Self::GT,
            B: &Self::GT,
            t: &[u8],
            m: &[u8],
            r: &Self::Scalar,
            c: &Self::Scalar,
            d: &Self::Scalar,
        ) -> Result<Self::GT, POPRFError>;
    }
}

#[derive(Clone, Debug)]
pub struct G2Scheme<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C> poprf::POPRFScheme for G2Scheme<C>
where
    C: PairingCurve,
{
    type Scalar = C::Scalar;
    type G1 = C::G1;
    type G2 = C::G2;
    type GT = C::GT;

    fn blind_ev(
        k: Self::Scalar,
        t: &[u8],
        a: Self::G2,
        b: Self::G2,
    ) -> Result<(Self::GT, Self::GT), POPRFError> {
        let mut h = Self::G1::new();
        h.map(t).map_err(|_| POPRFError::HashingError);
        let hk = h.mul(&k);
        // A <- e(H1(t)^k, a)
        let A = C::pair(&hk, &a);
        // B <- e(H1(t)^k, b)
        let B = C::pair(&hk, &b);

        Ok((A, B)) // rep <- (A, B)
    }

    fn finalize(
        v: &Self::G2,
        A: &Self::GT,
        B: &Self::GT,
        t: &[u8],
        m: &[u8],
        r: &Self::Scalar,
        c: &Self::Scalar,
        d: &Self::Scalar,
    ) -> Result<Self::GT, POPRFError> {
        // y_A = A^(r^(-1))
        let y_A = A.clone().mul(&r.inverse().ok_or(POPRFError::NoInverse)?);
        let mut h = Self::G1::new();
        h.map(t).map_err(|_| POPRFError::HashingError);
        // y_b <- B^(c^(-1)) e(H1(t), v^(-dc^(-1)))
        let y_B = B
            .clone()
            .mul(&c.inverse().ok_or(POPRFError::NoInverse)?)
            .add(C::pair(
                &h,
                &v.clone().mul(&d.clone().mul(&c.inverse().ok_or(POPRFError::NoInverse)?).negate())
            ));
        assert_eq!(y_A, y_B);

        Ok(y_A)
    }
}
