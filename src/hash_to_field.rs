//
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

//TODO: Make this work with any curve, not just bls377
pub trait HashToField {
    const NUM_TRIES: u8 = 255;

    type Scalar: Scalar<RHS = Self::Scalar>;

    fn hash_to_field(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(Self::Scalar, usize), HashError> {
        let num_bytes = Self::Scalar::zero().serialized_size();
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = Self::hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..Self::NUM_TRIES {
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

                return Ok((scalar_field, c as usize));
            }
        }

        Err(HashError::HashToFieldError)
    }

    fn hash_length(n: usize) -> usize {
        let bits = (n * 8) as f64 / 256.0;
        let rounded_bits = bits.ceil() * 256.0;
        rounded_bits as usize / 8
    }
}
