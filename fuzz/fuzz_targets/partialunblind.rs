#![no_main]
use libfuzzer_sys::fuzz_target;

use poprf::fuzz::{PartialUnblindFuzzInput, partialunblind};

fuzz_target!(|data: PartialUnblindFuzzInput| {
    partialunblind(data);
});

