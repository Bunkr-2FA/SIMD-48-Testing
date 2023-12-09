#![no_main]

use libfuzzer_sys::fuzz_target;
use secp256r1_verify::utils::secp256r1_instruction::verify;

fuzz_target!(|data: &[u8]| {
    // Call the verify function with the fuzzed data
    let _ = verify(data, &[&[0u8; 100]]);
    let _ = verify(data, &[&data]);
});