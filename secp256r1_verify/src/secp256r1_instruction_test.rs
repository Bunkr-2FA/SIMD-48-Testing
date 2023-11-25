
#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use solana_sdk::feature_set::FeatureSet;
    use crate::secp256r1_instruction::{self, verify, new_secp256r1_instruction};

    #[test]
    // Test that a valid signature is verified successfully
    fn successful_secp256r1_verification() {
        let signing_key = SigningKey::random(&mut OsRng);
        let feature_set = &FeatureSet::all_enabled();
        let message = b"Hello, world!";
        let instruction = new_secp256r1_instruction(&signing_key, message);
        let instruction_data = instruction.data.clone();
        let result = verify(&instruction_data, &[&[0u8; 100]], feature_set);
        assert!(result.is_ok(), "Verification failed when it should pass.");
    }

    #[test]
    // Test that a valid signature is verified successfully
    fn unsuccessful_secp256r1_verification() {
        let signing_key = SigningKey::random(&mut OsRng);
        let feature_set = &FeatureSet::all_enabled();
        let message = b"Hello, world!";
        let instruction = secp256r1_instruction::new_secp256r1_instruction(&signing_key, message);
        let mut instruction_data = instruction.data.clone();
        instruction_data[10] = instruction_data[11].wrapping_add(12); // this line modifies the instruction data to make the signature invalid
        let result = verify(&instruction_data, &[&[0u8; 100]], feature_set);
        assert!(result.is_err(), "Verification passed when it should fail.");
    }

    
}