pub mod utils;
use std::fs::File;
use crate::utils::create_der_encoded_signature;
use crate::utils::openssl_verify_vector;
use crate::utils::secp256r1_instruction::*;
use crate::utils::format_secp256r1_vector::*;
use crate::utils::report::*;
use std::io::{self, BufRead, BufReader};


    fn main() -> io::Result<()> {

        // Define paths to test vector files
        let paths = vec![
            "../test_vectors/vectors_random_valid.jsonl",
            "../test_vectors/vectors_wycheproof.jsonl",
            "../test_vectors/vectors_random_mixed.jsonl",
        ];
        

        // Create variables to keep track of mismatched vectors

        let mut p256_report = Report::new();
        let mut openssl_report = Report::new();

        println!("Running P256 & OpenSSL Implementations... \n");
        for path in paths {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                p256_report.total_vectors += 1;
                openssl_report.total_vectors += 1;
                let line = line?;
                let test_vector: TestVector = serde_json::from_str(&line).expect("JSON was not well-formatted");
                let instruction_data = new_secp256r1_instruction_from_vector(&test_vector);

                match verify(&instruction_data, &[&[0u8; 100]]) {
                    Ok(_) => {
                        if test_vector.valid == false {
                            // Uncomment for debugging
                            // print!("Path: {:?}\n", path);
                            // println!("SIMD-48 Verification passed for should-be invalid vector: {:#?}\n\n", test_vector);
                            p256_report.add_incorrect_vector(test_vector.clone());
                        }
                    },
                    Err(e) => {
                        if test_vector.valid == true {
                            // Uncomment for debugging
                            // println!("SIMD-48 Verification failed for should-be valid vector: {:#?}\n", test_vector);
                            // print!("Error: {:?}", e);
                            p256_report.add_incorrect_vector(test_vector.clone());
                        }
                    },
                }
            
                match openssl_verify_vector(&test_vector) {
                    Ok(_) => {
                        if test_vector.valid == false {
                            // Uncomment for debugging
                            // print!("Path: {:?}\n", path);
                            // println!("OpenSSL Verification passed for should-be invalid vector: {:#?}\n\n", test_vector);
                            // let der_signature = create_der_encoded_signature(&test_vector.r, &test_vector.s).unwrap();
                            // println!("DER encoded Sig: {:?}", hex::encode(&der_signature));
                            openssl_report.add_incorrect_vector(test_vector.clone());
                        }
                    },
                    Err(e) => {
                        if test_vector.valid == true {
                            // Uncomment for debugging
                            //println!("OpenSSL Verification failed for should-be valid vector: {:#?}\n", test_vector);
                            //print!("Error: {:?}", e);
                            //let der_signature = create_der_encoded_signature(&test_vector.r, &test_vector.s).unwrap();
                            //println!("DER encoded Sig: {:?}", hex::encode(&der_signature));
                            openssl_report.add_incorrect_vector(test_vector.clone());
                        }
                    },
                }
            }
        }
        write_report_to_file("../Reports/p256_report.json", &p256_report)?;
        println!("P256 Report generated ✅");
        println!("Total vectors: {}", p256_report.total_vectors);
        println!("Incorrect vectors: {}\n", p256_report.incorrect_count);

        write_report_to_file("../Reports/openssl_report.json", &openssl_report)?;
        println!("OpenSSL Report generated ✅");
        println!("Total vectors: {}", openssl_report.total_vectors);
        println!("Incorrect vectors: {}\n", openssl_report.incorrect_count);

        
        Ok(())
}
