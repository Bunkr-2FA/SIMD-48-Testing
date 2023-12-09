
#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256r1_verify::secp256r1_instruction::verify;
    use bytemuck::{bytes_of,Zeroable, Pod};
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::Signer};

    pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
    pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
    pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
    // bytemuck requires structures to be aligned
    pub const SIGNATURE_OFFSETS_START: usize = 2;
    pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

    #[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
    #[repr(C)]
    pub struct Secp256r1SignatureOffsets {
        pub signature_offset: u16,             // offset to compact secp256r1 signature of 64 bytes
        pub signature_instruction_index: u16,  // instruction index to find signature
        pub public_key_offset: u16,            // offset to compressed public key of 33 bytes
        pub public_key_instruction_index: u16, // instruction index to find public key
        pub message_data_offset: u16,          // offset to start of message data
        pub message_data_size: u16,            // size of message data
        pub message_instruction_index: u16,    // index of instruction data to get message data
    }
    pub fn new_secp256r1_instruction(signer: &SigningKey, message: &[u8]) -> Vec<u8> {
        let signature = signer.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature).to_vec();
        let pubkey = VerifyingKey::from(signer).to_encoded_point(true).to_bytes();
    
        assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
        assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);
    
        let mut instruction_data = Vec::with_capacity(
            DATA_START
                .saturating_add(SIGNATURE_SERIALIZED_SIZE)
                .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
                .saturating_add(message.len()),
        );
    
        let num_signatures: u8 = 1;
        let public_key_offset = DATA_START;
        let signature_offset = public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
        let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);
    
        // add padding byte so that offset structure is aligned
        instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));
    
        let offsets = Secp256r1SignatureOffsets {
            signature_offset: signature_offset as u16,
            signature_instruction_index: u16::MAX,
            public_key_offset: public_key_offset as u16,
            public_key_instruction_index: u16::MAX,
            message_data_offset: message_data_offset as u16,
            message_data_size: message.len() as u16,
            message_instruction_index: u16::MAX, 
        };
    
        instruction_data.extend_from_slice(bytes_of(&offsets));
    
        debug_assert_eq!(instruction_data.len(), public_key_offset);
    
        instruction_data.extend_from_slice(&pubkey);
    
        debug_assert_eq!(instruction_data.len(), signature_offset);
    
        instruction_data.extend_from_slice(&signature);
    
        debug_assert_eq!(instruction_data.len(), message_data_offset);
    
        instruction_data.extend_from_slice(message);
    
        
        instruction_data
    }

    
    #[test]
    // Test that a valid signature is verified successfully
    fn successful_secp256r1_verification() {
        let signing_key = SigningKey::random(&mut OsRng);
        let message = b"Hello, world!";
        let instruction_data = new_secp256r1_instruction(&signing_key, message);
        let instruction_data = instruction_data.clone();
        let result = verify(&instruction_data, &[&[0u8; 100]]);
        assert!(result.is_ok(), "Verification failed when it should pass.");
    }

    #[test]
    // Test that a valid signature is verified successfully
    fn unsuccessful_secp256r1_verification() {
        let signing_key = SigningKey::random(&mut OsRng);
        let message = b"Hello, world!";
        let instruction_data = new_secp256r1_instruction(&signing_key, message);
        let mut instruction_data = instruction_data.clone();
        instruction_data[10] = instruction_data[11].wrapping_add(12); // this line modifies the instruction data to make the signature invalid
        let result = verify(&instruction_data, &[&[0u8; 100]]);
        assert!(result.is_err(), "Verification passed when it should fail.");
    }

    
}