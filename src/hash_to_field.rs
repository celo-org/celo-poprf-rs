// use ark_bls12_377;
// use ark_ec::PairingEngine;
use ark_std::{end_timer, start_timer};
use bls_crypto::{BLSError, Hasher};
use byteorder::WriteBytesExt;
use log::error;
use log::trace;
use std::marker::PhantomData;
use thiserror::Error;
use threshold_bls::group::Scalar;

const NUM_TRIES: u8 = 255;

#[derive(Debug, Error)]
pub enum HashError {
    /// Hashing to field failed
    #[error("could not hash to scalar field")]
    HashToFieldError,

    /// An IO error
    #[error("io error {0}")]
    IoError(#[from] std::io::Error),

    /// Error while hashing
    #[error("error in hasher {0}")]
    HashingError(#[from] bls_crypto::BLSError),
}

pub trait HashToField {
    type Output: Scalar<RHS = Self::Output>;

    fn hash_to_field(&self, domain: &[u8], message: &[u8]) -> Result<Self::Output, HashError>;
}

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
#[derive(Clone)]
pub struct TryAndIncrement<'a, H, F> {
    hasher: &'a H,
    params: PhantomData<F>,
}

impl<'a, H, F> TryAndIncrement<'a, H, F>
where
    H: Hasher<Error = BLSError>,
    F: Scalar,
{
    /// Instantiates a new Try-and-increment hasher with the provided hashing method
    /// and curve parameters based on the type
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement {
            hasher: h,
            params: PhantomData,
        }
    }
}

impl<'a, H, F> HashToField for TryAndIncrement<'a, H, F>
where
    H: Hasher<Error = BLSError>,
    F: Scalar<RHS = F>,
{
    type Output = F;

    fn hash_to_field(&self, domain: &[u8], message: &[u8]) -> Result<Self::Output, HashError> {
        let num_bytes = Self::Output::zero().serialized_size();
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let candidate_hash =
                self.hasher
                    .hash(domain, &[&counter, message].concat(), hash_bytes)?;

            if let Some(scalar_field) =
                Self::Output::from_random_bytes(&candidate_hash[..num_bytes])
            {
                trace!(
                    "succeeded hashing \"{}\" to scalar field in {} tries",
                    hex::encode(message),
                    c
                );
                end_timer!(hash_loop_time);

                return Ok(scalar_field);
            }
        }

        Err(HashError::HashToFieldError)
    }
}

/// Given `n` bytes, it returns the value rounded to the nearest multiple of 256 bits (in bytes)
/// e.g. 1. given 48 = 384 bits, it will return 64 bytes (= 512 bits)
///      2. given 96 = 768 bits, it will return 96 bytes (no rounding needed since 768 is already a
///         multiple of 256)
fn hash_length(n: usize) -> usize {
    let bits = (n * 8) as f64 / 256.0;
    let rounded_bits = bits.ceil() * 256.0;
    rounded_bits as usize / 8
}

#[cfg(test)]
mod tests {
    use crate::bls12_377::Scalar;
    use crate::hash_to_field::{HashToField, TryAndIncrement};
    use bls_crypto::hashers::DirectHasher;

    #[test]
    fn test_hash_to_field() -> Result<(), Box<dyn std::error::Error>> {
        struct Case {
            // 8-bytes personalization string.
            domain: &'static [u8],
            message: &'static [u8],
            expected: &'static [u8],
        }

        let cases = vec![
            Case {
                domain: b"H2FTEST1",
                message: b"Hash to field test message",
                expected: b"7a76c4b0e7af6d8db05a7f38f30f3aabba99fcc55cc62b8068a5eb3d81396d07",
            },
            Case {
                domain: b"H2FTEST2",
                message: b"Hash to field test message",
                expected: b"6b5a6b198eb79c293db3bd95eb9ae59ca2da80e98e815d0462f6421eb81c4710",
            },
            Case {
                domain: b"H2FTEST1",
                message: b"Hash to field test alternative message",
                expected: b"e848153119b3864d5853447b62f5358063f3c181ff2f035dd5ce8eb1708c3e02",
            },
        ];

        for case in cases.iter() {
            let expected_hash: Scalar = bincode::deserialize(&hex::decode(case.expected)?)?;

            let hasher = TryAndIncrement::<_, Scalar>::new(&DirectHasher);
            let hash = hasher.hash_to_field(case.domain, case.message).unwrap();
            println!("scalar: {}", hex::encode(bincode::serialize(&hash)?));
            assert_eq!(expected_hash, hash);
        }
        Ok(())
    }
}
