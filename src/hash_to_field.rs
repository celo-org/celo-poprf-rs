// use ark_bls12_377;
// use ark_ec::PairingEngine;
use ark_ff::fields::Field;
use ark_std::{end_timer, start_timer};
use bls_crypto::{hashers::DirectHasher, Hasher};
use byteorder::WriteBytesExt;
use log::error;
use log::trace;
use thiserror::Error;
use threshold_bls::group::{Element, Scalar};

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
    type Scalar;

    fn hash_to_field(&self, domain: &[u8], message: &[u8]) -> Result<Self::Scalar, HashError>;
}

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
//TODO: Make this work with any curve, not just bls377
#[derive(Clone)]
pub struct TryAndIncrement<'a, H> {
    hasher: &'a H,
}

impl<'a, H> TryAndIncrement<'a, H>
where
    H: Hasher<Error = HashError>,
{
    /// Instantiates a new Try-and-increment hasher with the provided hashing method
    /// and curve parameters based on the type
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement { hasher: h }
    }
}

impl<'a, H> HashToField for TryAndIncrement<'a, H>
where
    H: Hasher<Error = HashError>,
{
    type Scalar = Box<dyn Scalar<RHS=Self::Scalar>>;

    fn hash_to_field(&self, domain: &[u8], message: &[u8]) -> Result<Self::Scalar, HashError> {
        let num_bytes = Self::Scalar::zero().serialized_size();
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let candidate_hash =
                DirectHasher.hash(domain, &[&counter, message].concat(), hash_bytes)?;

            if let Some(scalar_field) =
                Self::Scalar::from_random_bytes(&candidate_hash[..num_bytes])
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
    #[test]
    fn test_hash_to_field() {}
}
