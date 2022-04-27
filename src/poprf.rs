use crate::{
    api::Scheme,
    hash_to_field::{HashToField, TryAndIncrement},
    PoprfError,
};
use bls_crypto::hashers::DirectHasher;
use rand::RngCore;
use std::{fmt::Debug, marker::PhantomData};
use threshold_bls::{
    group::{Element, PrimeOrder, PairingCurve, Point, Scalar},
    poly::{Eval, Poly},
    sig::Share,
};

/// 8-byte constant hashing domain for the proof of related query subprotocol.
const NIZK_HASH_DOMAIN: &[u8] = b"PoRQH2FF";

pub trait Poprf: Scheme {
    // TODO(victor): Figure out how to refactor to avoid this complex return type.
    #[allow(clippy::type_complexity)]
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
        PoprfError,
    > {
        let r = Self::Private::rand(rng);
        let c = Self::Private::rand(rng);
        let d = Self::Private::rand(rng);

        // h = H(msg)
        let h = {
            let mut h = Self::Public::one();
            h.map(msg).map_err(|_| PoprfError::HashingError)?;
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
    // TODO(victor): Figure out how to refactor to avoid this complex return type.
    #[allow(clippy::type_complexity)]
    fn prove<R: RngCore>(
        a: Self::Public,
        b: &Self::Public,
        x: Self::Private,
        y: Self::Private,
        rng: &mut R,
    ) -> Result<(Self::Private, Self::Private, Self::Private), PoprfError> {
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
    ) -> Result<bool, PoprfError> {
        // v = g2^s1 * a^s2 * b^z
        let v = {
            let mut g2s1 = Self::Public::one();
            g2s1.mul(s1);
            let mut as2 = a.clone();
            as2.mul(s2);
            let mut bz = b.clone();
            bz.mul(z);
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

    fn eval(k: &Self::Private, t: &[u8], a: &[u8]) -> Result<Self::Evaluation, PoprfError>;

    fn blind_ev(
        k: &Self::Private,
        t: &[u8],
        a: &Self::Public,
        b: &Self::Public,
    ) -> Result<(Self::Evaluation, Self::Evaluation), PoprfError>;

    fn aggregate(
        threshold: usize,
        shares: &[Share<Self::Evaluation>],
    ) -> Result<Self::Evaluation, PoprfError> {
        if threshold > shares.len() {
            return Err(PoprfError::NotEnoughResponses(shares.len(), threshold));
        }

        let shares: Vec<Eval<Self::Evaluation>> = shares
            .iter()
            .map(|share| Eval {
                index: share.index,
                value: share.private.clone(),
            })
            .collect();
        let res = Poly::recover(threshold, shares)?;

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
    ) -> Result<Self::Evaluation, PoprfError>;
}

// G2Scheme implements pairings with public keys over G2
#[derive(Clone, Debug)]
pub struct G2Scheme<C: PairingCurve> {
    m: PhantomData<C>,
}

impl<C: PairingCurve> Scheme for G2Scheme<C> 
where
    C::GT : PrimeOrder
{
    type Private = C::Scalar;
    type Public = C::G2;
    type Evaluation = C::GT;
}

impl<C> Poprf for G2Scheme<C>
where
    C: PairingCurve,
    C::GT: PrimeOrder,
{
    #[allow(non_snake_case)]
    fn eval(k: &Self::Private, t: &[u8], m: &[u8]) -> Result<Self::Evaluation, PoprfError> {
        let mut h1 = C::G1::new();
        let mut h2 = C::G2::new();
        h1.map(t).map_err(|_| PoprfError::HashingError)?;
        h1.mul(k);
        h2.map(m).map_err(|_| PoprfError::HashingError)?;
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
    ) -> Result<(Self::Evaluation, Self::Evaluation), PoprfError> {
        let mut h = C::G1::new();
        h.map(t).map_err(|_| PoprfError::HashingError)?;
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
    ) -> Result<Self::Evaluation, PoprfError> {
        if !A.in_correct_subgroup() || !B.in_correct_subgroup() {
            return Err(PoprfError::WrongSubgroupError)
        }
        // y_A = A^(r^(-1))
        let y_A = {
            let r_inv = r.inverse().ok_or(PoprfError::NoInverse)?;
            let mut y_A = A.clone();
            y_A.mul(&r_inv);
            y_A
        };

        // h = H_1(t)
        let h = {
            let mut h = C::G1::new();
            h.map(t).map_err(|_| PoprfError::HashingError)?;
            h
        };

        // y_B <- B^(c^(-1)) e(H1(t), v^(-dc^(-1)))
        let y_B = {
            let c_inv = c.inverse().ok_or(PoprfError::NoInverse)?;

            let mut dc = d.clone();
            dc.mul(&c_inv);
            dc.negate();

            let mut vdc = v.clone();
            vdc.mul(&dc);

            let mut y_B = B.clone();
            y_B.mul(&c_inv);
            y_B.add(&C::pair(&h, &vdc));
            y_B
        };

        if y_A != y_B {
            return Err(PoprfError::VerifyError);
        }

        Ok(y_A)
    }
}
