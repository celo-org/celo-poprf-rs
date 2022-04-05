use crate::hash_to_field::{HashToField, TryAndIncrement};
use crate::POPRFError;
use bls_crypto::hashers::DirectHasher;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, marker::PhantomData};
use threshold_bls::{
    group::{Element, PairingCurve, Point, Scalar},
    poly::{Eval, Poly},
    sig::Share,
};

/// 8-byte constant hashing domain for the proof of related query subprotocol.
const NIZK_HASH_DOMAIN: &'static [u8] = b"PoRQH2FF";

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
    fn keypair<R: RngCore>(rng: &mut R) -> (Self::Private, Self::Public) {
        let private = Self::Private::rand(rng);

        let mut public = Self::Public::one();
        public.mul(&private);

        (private, public)
    }
}

pub mod poprf {
    use super::*;

    pub trait POPRF: Scheme {
        fn req<R: RngCore>(
            msg: &[u8],
            rng: &mut R,
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
            let r = Self::Private::rand(rng);
            let c = Self::Private::rand(rng);
            let d = Self::Private::rand(rng);

            // h = H(msg)
            let h = {
                let mut h = Self::Public::one();
                h.map(msg).map_err(|_| POPRFError::HashingError)?;
                h
            };

            // a = h^r
            let a = {
                let mut a = h.clone();
                a.mul(&r);
                a
            };

            // b = h^c * g2^d
            let b = {
                let mut b = h;
                let mut g2d = Self::Public::one();
                b.mul(&c);
                g2d.mul(&d);
                b.add(&g2d);
                b
            };

            Ok((r, c, d, a, b))
        }

        // Prove(a, b, c/r, d)
        fn prove<R: RngCore>(
            a: Self::Public,
            b: &Self::Public,
            x: Self::Private,
            y: Self::Private,
            rng: &mut R,
        ) -> Result<(Self::Private, Self::Private, Self::Private), POPRFError> {
            let v1 = Self::Private::rand(rng);
            let v2 = Self::Private::rand(rng);

            // v = g2^v1 * a^v2
            let v = {
                let mut g2v1 = Self::Public::one();
                let mut av2 = a.clone();
                g2v1.mul(&v1);
                av2.mul(&v2);
                let mut v = g2v1;
                v.add(&av2);
                v
            };

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&Self::Public::one())?;
            let v_ser = bincode::serialize(&v)?;
            let a_ser = bincode::serialize(&a)?;
            let b_ser = bincode::serialize(&b)?;
            let concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            let hasher = TryAndIncrement::new(&DirectHasher);
            let z = hasher.hash_to_field(NIZK_HASH_DOMAIN, &concatenate)?;

            // s1 = v1 - y * z
            let s1 = {
                let mut s1 = v1;
                let mut yz = y;
                yz.mul(&z);
                s1.sub(&yz);
                s1
            };

            // s2 = v2 - x * z
            let s2 = {
                let mut s2 = v2;
                let mut xz = x;
                xz.mul(&z);
                s2.sub(&xz);
                s2
            };

            Ok((z, s1, s2))
        }

        fn verify(
            a: Self::Public,
            b: Self::Public,
            z: &Self::Private,
            s1: &Self::Private,
            s2: &Self::Private,
        ) -> Result<bool, POPRFError> {
            // v = g2^s1 * a^s2 * b^z
            let v = {
                let mut g2s1 = Self::Public::one();
                g2s1.mul(&s1);
                let mut as2 = a.clone();
                as2.mul(&s2);
                let mut bz = b.clone();
                bz.mul(&z);
                let mut v = g2s1;
                v.add(&as2);
                v.add(&bz);
                v
            };

            // Concatenate (g2 || v || a || b)
            let g2_ser = bincode::serialize(&Self::Public::one())?;
            let v_ser = bincode::serialize(&v)?;
            let a_ser = bincode::serialize(&a)?;
            let b_ser = bincode::serialize(&b)?;
            let concatenate: Vec<u8> = [g2_ser, v_ser, a_ser, b_ser].concat();

            let hasher = TryAndIncrement::new(&DirectHasher);
            let h = hasher.hash_to_field(NIZK_HASH_DOMAIN, &concatenate)?;

            Ok(*z == h)
        }

        fn eval(k: &Self::Private, t: &[u8], a: &[u8]) -> Result<Self::Evaluation, POPRFError>;

        fn blind_ev(
            k: &Self::Private,
            t: &[u8],
            a: &Self::Public,
            b: &Self::Public,
        ) -> Result<(Self::Evaluation, Self::Evaluation), POPRFError>;

        fn aggregate(
            threshold: usize,
            shares: &[Share<Self::Evaluation>],
        ) -> Result<Self::Evaluation, POPRFError> {
            if threshold > shares.len() {
                return Err(POPRFError::NotEnoughResponses(shares.len(), threshold));
            }

            let valid_shares: Vec<Eval<Self::Evaluation>> = shares
                .iter()
                .map(|share| {
                    Ok(Eval {
                        index: share.index,
                        value: share.private.clone(),
                    })
                })
                .collect::<Result<_, POPRFError>>()?;
            let res = Poly::recover(threshold, valid_shares)?;

            Ok(res)
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

// G2Scheme implements pairings with public keys over G2
#[derive(Clone, Debug)]
pub struct G2Scheme<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C: PairingCurve> Scheme for G2Scheme<C> {
    type Private = C::Scalar;
    type Public = C::G2;
    type Evaluation = C::GT;
}

impl<C> poprf::POPRF for G2Scheme<C>
where
    C: PairingCurve,
{
    #[allow(non_snake_case)]
    fn eval(k: &Self::Private, t: &[u8], m: &[u8]) -> Result<Self::Evaluation, POPRFError> {
        let mut h1 = C::G1::new();
        let mut h2 = C::G2::new();
        h1.map(t).map_err(|_| POPRFError::HashingError)?;
        h1.mul(k);
        h2.map(m).map_err(|_| POPRFError::HashingError)?;
        // A <- e(H1(t)^k, H2(m))
        let A = C::pair(&h1, &h2);

        Ok(A)
    }

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
        if y_A != y_B {
            return Err(POPRFError::VerifyError);
        }

        Ok(y_A)
    }
}
