#![no_main]
use libfuzzer_sys::fuzz_target;

use poprf::fuzz::{PoprfFuzzInput, poprfscheme};

fuzz_target!(|data: PoprfFuzzInput| {
    poprfscheme(data);
});

