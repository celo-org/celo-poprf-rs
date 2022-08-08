#![no_main]
use libfuzzer_sys::fuzz_target;

use poprf::fuzz::hash_to_field;

fuzz_target!(|data: &[u8]| {
    hash_to_field(data);
});
