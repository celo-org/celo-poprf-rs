use crate::ffi::wasm;

static STATIC_TAG: &[u8] = b"FUZZING STATIC TAG";

#[derive(arbitrary::Arbitrary, Debug)]
pub struct UnblindRespInput {
    blinded_resp_buf: Vec<u8>,
}

pub fn unblind_resp(input: UnblindRespInput) {
    // TODO(victor): Figure out a good way to make these values constant between calls.
    let static_keypair: wasm::Keypair = wasm::keygen(b"FUZZING STATIC KEYGEN SEED").unwrap();
    let static_blinded_msg: wasm::BlindedMessage =
        wasm::blind_msg(b"FUZZING STATIC MSG", b"FUZZING STATIC BLINDING SEED").unwrap();

    wasm::unblind_resp(
        &static_keypair.public_key(),
        &static_blinded_msg.blinding_factor(),
        STATIC_TAG,
        &input.blinded_resp_buf,
    )
    .unwrap_err();
}
