#![no_main]

use libfuzzer_sys::fuzz_target;
use secp256r1_verify::utils::secp256r1_instruction::verify;
use hex;

fuzz_target!(|data: &[u8]| {
    // Call the verify function with the fuzzed data
    let result1 = verify(data, &[&[0u8; 100]]);
    let result2 = verify(data, &[&data]);

    // If num_sigs is not 0, the the result should be an error
    if data.len() > 0 && data[0] != 0 {
        assert!(result1.is_err());
        assert!(result2.is_err());
    }
});