#![no_main]
use libfuzzer_sys::fuzz_target;

use poprf::ffi::fuzz::{UnblindRespInput, unblind_resp};

fuzz_target!(|data: UnblindRespInput| {
    unblind_resp(data);
});
