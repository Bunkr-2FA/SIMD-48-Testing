use bytemuck::bytes_of;
use hex;
use p256::elliptic_curve::bigint::Encoding;
use serde::{Deserialize, Serialize};
use crate::utils::{COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START, SIGNATURE_SERIALIZED_SIZE, Secp256r1SignatureOffsets};
use p256::elliptic_curve::bigint::U256;



#[derive(Serialize, Deserialize, Debug)]
pub struct TestVector {
    pub x: String,
    pub y: String,
    pub r: String,
    pub s: String,
    pub hash: String,
    pub valid: bool,
    pub msg: String,
    pub comment: String,
}



pub fn new_secp256r1_instruction_from_vector(test_vector: &TestVector) -> Vec<u8> {

    // Define curve order so we can normalize s 
    const CURVE_ORDER_N:U256 = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let half_n:U256 = CURVE_ORDER_N >> 1;

    let signature_s:U256 = U256::from_be_hex(&test_vector.s);

    // Normalize s if necessary
    let normalised_s:U256 = if signature_s > half_n {
        CURVE_ORDER_N.wrapping_sub(&signature_s)
    } else {
        signature_s
    };
    let normalised_s_bytes = normalised_s.to_be_bytes();
    let signature_r_bytes = hex::decode(&test_vector.r).unwrap();

    // Create signature bytes from r and s
    let signature_bytes = vec![signature_r_bytes.as_slice(), &normalised_s_bytes].concat();

    // Parse out the y-coordinate 
    let y_bytes = hex::decode(&test_vector.y).unwrap();

    // Determine the prefix based on the last bit of the y coordinate
    // Note: "02" and "03" signify if the y-coord is even or odd
    let prefix = if y_bytes.last().unwrap() % 2 == 0 { "02" } else { "03" };


    // Compress the public key: prefix + x coordinate
    let compressed_pubkey_hex = format!("{}{}", prefix, test_vector.x);
    let compressed_pubkey_bytes = hex::decode(&compressed_pubkey_hex).unwrap();

    // Assert correct lengths for pubkey and signature
    assert_eq!(compressed_pubkey_bytes.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature_bytes.len(), SIGNATURE_SERIALIZED_SIZE);
    
    // Decode message into bytes
    let message = hex::decode(test_vector.msg.as_str()).unwrap();

    // Create correctly sized Vex
    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    // Create offset values to later add to instruction
    let num_signatures: u8 = 1;
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    // add padding byte so that offset structure is aligned
    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));


    // Create offset object
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

    instruction_data.extend_from_slice(&compressed_pubkey_bytes);

    debug_assert_eq!(instruction_data.len(), signature_offset);

    instruction_data.extend_from_slice(&signature_bytes);

    debug_assert_eq!(instruction_data.len(), message_data_offset);

    instruction_data.extend_from_slice(&message);

    instruction_data
}