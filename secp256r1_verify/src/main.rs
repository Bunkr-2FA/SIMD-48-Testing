pub mod utils;
use std::fs::File;
use std::io::Write;
use utils::secp256r1_instruction::*;
use utils::format_secp256r1_vector::*;
use std::io::{self, BufRead, BufReader};


    fn main() -> io::Result<()> {

        // Define paths to test vector files
        let paths = vec![
            "../test_vectors/vectors_random_valid.jsonl",
            "../test_vectors/vectors_wycheproof.jsonl",
        ];
        

        // Create variables to keep track of mismatched vectors
        let mut invalid_vector_valid = 0;
        let mut valid_vector_invalid = 0;
        let mut counter = 0;

        for path in paths {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut line_num = 0;
            for line in reader.lines() {
                line_num += 1;
                let line = line?;
                let test_vector: TestVector = serde_json::from_str(&line).expect("JSON was not well-formatted");
    
                let instruction_data = new_secp256r1_instruction_from_vector(&test_vector);
                let file_name = format!("fuzz/corpus/fuzz_target_1/test_vector_{}", counter);
                let mut file = File::create(file_name)?;
                file.write_all(&instruction_data)?;
                counter += 1;

                match verify(&instruction_data, &[&[0u8; 100]]) {
                    Ok(_) => {
                        if test_vector.valid == false {
                            print!("Path: {:?}\n", path);
                            println!("Line: {}", line_num);
                            println!("Verification passed for should-be invalid vector: {:#?}\n\n", test_vector);
                            invalid_vector_valid += 1;
                        }
                    },
                    Err(e) => {
                        if test_vector.valid == true {
                            println!("Verification failed for should-be valid vector: {:#?}\n", test_vector);
                            print!("Error: {:?}", e);
                            valid_vector_invalid += 1;
                        }
                    },
                }
            }
        }
        println!("{} should-be invalid vectors were valid", invalid_vector_valid);
        println!("{} should-be valid vectors were invalid", valid_vector_invalid);
        Ok(())
}
