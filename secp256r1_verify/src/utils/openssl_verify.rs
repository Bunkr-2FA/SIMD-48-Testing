use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::{PKey};
use openssl::nid::Nid;
use openssl::sign::Verifier;
use std::error::Error;
use std::vec;
use crate::utils::format_secp256r1_vector::*;


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
        Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Signature verification failed")))
    }
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
        assert!(result.is_err(), "Verification passed for an invalid vector.");
    }
}
