use threshold_bls::group::Scalar;

pub trait HashToField {
    const NUM_TRIES: u8 = 255;

    fn hash_to_field(&self, domain: &[u8], message: &[u8]) -> Result<Scalar, Error> {
        //extra data?
        let num_bytes = Scalar::zero().serialized_size(); //TODO: serialize
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = Self::hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let candidate_hash = self.hasher.hash(
                domain,
                &[&counter, extra_data, &message].concat(),
                hash_bytes,
            )?;

            if let Some(p) = Scalar::from_be_bytes_mod_order(&candidate_hash[..num_bytes]) { // TODO: from_bytes
                trace!(
                    "succeeded hashing \"{}\" to scalar field in {} tries",
                    hex::encode(message),
                    c
                );
                end_timer!(hash_loop_time);

                // let scaled = p.scale_by_cofactor();
                // if scaled.is_zero() {
                //     continue;
                // }
                //
                // return Ok((scaled, c as usize));
            }



        }

        Err(Error::HashingError)
    }

    fn hash_length(n: usize) -> usize {
        let bits = (n * 8) as f64 / 256.0;
        let rounded_bits = bits.ceil() * 256.0;
        rounded_bits as usize / 8
    }
}
