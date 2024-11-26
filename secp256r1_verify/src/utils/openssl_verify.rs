use crate::utils::format_secp256r1_vector::*;
use crate::utils::{
    get_data_slice, PrecompileError, Secp256r1SignatureOffsets, COMPRESSED_PUBKEY_SERIALIZED_SIZE,
    SIGNATURE_OFFSETS_SERIALIZED_SIZE, SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use std::error::Error;
use std::vec;

// Order as defined in SEC2: 2.7.2 Recommended Parameters secp256r1
pub const SECP256R1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// Computed SECP256R1_ORDER - 1
pub const SECP256R1_ORDER_MINUS_ONE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
];

// Computed half order
const SECP256R1_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];
// Field size in bytes
const FIELD_SIZE: usize = 32;

pub fn create_der_encoded_signature(r_hex: &str, s_hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // Decode the hex strings to byte arrays
    let r_bytes = hex::decode(r_hex)?;
    let s_bytes = hex::decode(s_hex)?;

    // Create BigNum objects from the byte arrays
    let r_bignum = BigNum::from_slice(&r_bytes)?;
    let s_bignum = BigNum::from_slice(&s_bytes)?;

    // Create an ECDSA signature object from the ASN.1 integers
    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r_bignum, s_bignum)?;

    // DER encode the ECDSA signature
    let der_encoded_sig = ecdsa_sig.to_der()?;

    Ok(der_encoded_sig)
}

pub fn openssl_verify_vector(vector: &TestVector) -> Result<(), Box<dyn Error>> {
    // Load the P-256 curve
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

    // Create a BigNum context
    let mut ctx = BigNumContext::new()?;

    // Decode hex values of x, y, r, and s
    let x_bytes = hex::decode(&vector.x)?;
    let y_bytes = hex::decode(&vector.y)?;

    // Combine x and y coordinates into an uncompressed point format
    let mut point_bytes = vec![0x04]; // Prefix for uncompressed point
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    // Create an EcPoint from the point bytes
    let public_key_point = EcPoint::from_bytes(&group, &point_bytes, &mut ctx)?;

    // Create an EcKey from the EcPoint
    let public_key = EcKey::from_public_key(&group, &public_key_point).unwrap();

    let der_signature = create_der_encoded_signature(&vector.r, &vector.s)?;

    //println!("DER Signature: {:x?}", hex::encode(&der_signature));

    // Convert EcKey<Public> to PKey
    let pkey = PKey::from_ec_key(public_key)?;

    // Pring pkey in hex
    //println!("PKey: {:x?}", hex::encode(pkey.public_key_to_der().unwrap()));

    //println!("Message: {:x?}", &vector.msg);
    // Get message bytes
    let message_bytes = hex::decode(&vector.msg)?;

    // Pring message hashed
    //println!("Message Hashed: {:x?}", hex::encode(openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &message_bytes).unwrap()));

    // Create a verifier object and verify the signature
    let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)?;
    verifier.update(&message_bytes)?;

    // Perform the verification
    if verifier.verify(&der_signature)? {
        Ok(())
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Signature verification failed",
        )))
    }
}

pub fn op_verify(data: &[u8], instruction_datas: &[&[u8]]) -> Result<(), PrecompileError> {
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    if num_signatures > 8 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);

    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }

    // Parse half order from constant
    let half_order: BigNum =
        BigNum::from_slice(&SECP256R1_HALF_ORDER).map_err(|_| PrecompileError::InvalidSignature)?;

    // Parse order - 1 from constant
    let order_minus_one: BigNum = BigNum::from_slice(&SECP256R1_ORDER_MINUS_ONE)
        .map_err(|_| PrecompileError::InvalidSignature)?;

    // Create a BigNum for 1
    let one = BigNum::from_u32(1).map_err(|_| PrecompileError::InvalidSignature)?;

    // Define curve group
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|_| PrecompileError::InvalidSignature)?;
    let mut ctx = BigNumContext::new().map_err(|_| PrecompileError::InvalidSignature)?;

    for i in 0..num_signatures {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        // bytemuck wants structures aligned
        let offsets: &Secp256r1SignatureOffsets = bytemuck::try_from_bytes(&data[start..end])
            .map_err(|_| PrecompileError::InvalidDataOffsets)?;

        // Parse out signature
        let signature = get_data_slice(
            data,
            instruction_datas,
            offsets.signature_instruction_index,
            offsets.signature_offset,
            SIGNATURE_SERIALIZED_SIZE,
        )?;

        // Parse out pubkey
        let pubkey = get_data_slice(
            data,
            instruction_datas,
            offsets.public_key_instruction_index,
            offsets.public_key_offset,
            COMPRESSED_PUBKEY_SERIALIZED_SIZE,
        )?;

        // Parse out message
        let message = get_data_slice(
            data,
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        let r_bignum = BigNum::from_slice(&signature[..FIELD_SIZE])
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let s_bignum = BigNum::from_slice(&signature[FIELD_SIZE..])
            .map_err(|_| PrecompileError::InvalidSignature)?;

        // Check that r and s are within the proper range and enforce a low-S value
        let within_range = r_bignum >= one
            && r_bignum <= order_minus_one
            && s_bignum >= one
            && s_bignum <= half_order;

        if !within_range {
            return Err(PrecompileError::InvalidSignature);
        }

        // Create an ECDSA signature object from the ASN.1 integers
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r_bignum, s_bignum)
            .and_then(|sig| sig.to_der())
            .map_err(|_| PrecompileError::InvalidSignature)?;

        let public_key_point = EcPoint::from_bytes(&group, pubkey, &mut ctx)
            .map_err(|_| PrecompileError::InvalidPublicKey)?;
        let public_key = EcKey::from_public_key(&group, &public_key_point)
            .map_err(|_| PrecompileError::InvalidPublicKey)?;
        let public_key_as_pkey =
            PKey::from_ec_key(public_key).map_err(|_| PrecompileError::InvalidPublicKey)?;

        let mut verifier =
            Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key_as_pkey)
                .map_err(|_| PrecompileError::InvalidSignature)?;
        verifier
            .update(message)
            .map_err(|_| PrecompileError::InvalidSignature)?;

        if !verifier
            .verify(&ecdsa_sig)
            .map_err(|_| PrecompileError::InvalidSignature)?
        {
            return Err(PrecompileError::InvalidSignature);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;

    #[test]
    fn successful_openssl_secp256r1_verification_from_crypto_subtle() {
        let test_vector_json = r#"{
        "der": "",
        "x":"0ed20892f8606b47fdfdea4d102518a6b48e70dc320cf0154a23cdd39468d409",
        "y":"5dd3075b0f3670a6f348a8c1af7d7d3ebf153152055b965fc8f945092e9e79eb",
        "r":"ed090342d9baa6cf3ffa84c1914576c575bef7f3b8fd7cf25bbdee27e40172c8",
        "s":"86e0db2259d8ebb658351590d8ae0861b40fc354627c3a821876e9ce25a12596",
        "hash":"3fec5769b5cf4e310a7d150508e82fb8e3eda1c2c94c61492d3bd8aea99e06c9",
        "valid":true,
        "msg":"deadbeef0000",
        "comment":"generation 0"
    }"#;

        let test_vector: TestVector = from_str(test_vector_json).expect("Failed to parse JSON");
        println!("Test vector: {:#?}\n", test_vector);
        let result = openssl_verify_vector(&test_vector);
        assert!(result.is_ok(), "Verification failed for a valid vector.");
    }

    #[test]
    fn successful_openssl_secp256r1_verification_from_wycheproof() {
        let test_vector_json = r#"{
            "der":"",
            "x":"2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            "y":"c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
            "r":"2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
            "s":"4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
            "hash":"26d5db7c72ff1b658469bcb33844cafc9ded063ed62f2c6e8f8d971519c27873",
            "valid":true,
            "msg":"313233343030",
            "comment":"wycheproof_v1/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #1: signature malleability"
        }"#;
        let test_vector: TestVector = from_str(test_vector_json).expect("Failed to parse JSON");
        println!("Test vector: {:#?}\n", test_vector);
        let result = openssl_verify_vector(&test_vector);
        assert!(result.is_ok(), "Verification failed for a valid vector.");
    }

    #[test]
    fn unsuccessful_openssl_secp256r1_verification() {
        let test_vector_json = r#"{
            "der":"",
            "x":"2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            "y":"c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
            "r":"d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739",
            "s":"b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
            "hash":"26d5db7c72ff1b658469bcb33844cafc9ded063ed62f2c6e8f8d971519c27873",
            "valid":false,"msg":"313233343030",
            "comment":"wycheproof_v1/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #4: replaced r by n - r"
        }"#;
        let test_vector: TestVector = from_str(test_vector_json).expect("Failed to parse JSON");
        let result = openssl_verify_vector(&test_vector);
        // Print result
        println!("Test vector: {:#?}\n", test_vector);
        println!("Result: {:?}", result);
        assert!(
            result.is_err(),
            "Verification passed for an invalid vector."
        );
    }
}
