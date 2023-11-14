mod secp256r1_instruction;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use secp256r1_instruction::verify;
use solana_sdk::feature_set::FeatureSet;

fn main() {
    let signing_key = SigningKey::random(&mut OsRng);
    let feature_set = &FeatureSet::all_enabled();
    let message = b"Hello, world!";
    let instruction = secp256r1_instruction::new_secp256r1_instruction(&signing_key, message);
    let mut instruction_data = instruction.data.clone();
    instruction_data[10] = instruction_data[11].wrapping_add(12);
    let result = verify(&instruction_data, &[&[0u8; 100]], feature_set);
    println!("result: {:?}", result);
}
