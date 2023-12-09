use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::fs::File;
use std::io::{stdin, BufRead, BufReader};
use secp256r1_verify::utils::*;



pub fn get_test_vectors() -> Vec<TestVector> {
    // Define paths to test vector files
    let paths = vec![
    "../test_vectors/vectors_random_valid.jsonl", 
    "../test_vectors/vectors_wycheproof.jsonl"
    ];
    let mut test_vectors = Vec::new();

    // Read and parse test vectors from files
    for path in paths {
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.unwrap();
            let test_vector: TestVector = serde_json::from_str(&line).expect("JSON was not well-formatted");
            test_vectors.push(test_vector);
        }
    }
    test_vectors
}

pub fn bench_secp256r1_verify(c: &mut Criterion) {
    let test_vectors = get_test_vectors();
    let total_vectors = test_vectors.len();
    
    // Benchmark the entire execution of all test vectors as a single benchmark
    c.bench_with_input(BenchmarkId::new("secp256r1_verify", total_vectors), &test_vectors, |b, tvs| {
        b.iter(|| {
            for tv in tvs {
                let instruction_data = new_secp256r1_instruction_from_vector(tv);
                let _ = secp256r1_instruction::verify(&instruction_data, &[&[0u8; 100]]);
            }
        });
    });
}

fn calculate_compute() {
    // Ask the user for the upper bound value
    println!("Enter the upper bound time in milliseconds:");
    
    // Read the upper bound from the console
    let mut upper_bound_str = String::new();
    stdin().read_line(&mut upper_bound_str).expect("Failed to read line");
    let upper_bound_ms: f64 = upper_bound_str.trim().parse().expect("Please enter a valid number!");

    // Ask the user for the number of test vectors
    println!("Enter the total number of test vectors:");
    
    // Read the number of test vectors from the console
    let mut total_vectors_str = String::new();
    stdin().read_line(&mut total_vectors_str).expect("Failed to read line");
    let total_vectors: usize = total_vectors_str.trim().parse().expect("Please enter a valid number!");

    // Convert milliseconds to nanoseconds and calculate the average time per verification
    let upper_bound_ns = upper_bound_ms * 1_000_000.0;
    let avg_time_per_verify_ns = upper_bound_ns / total_vectors as f64;

    println!("Average time per verify (using upper bound): {:.2} ns", avg_time_per_verify_ns);
    println!("At 1 CU / 33 ns, this is equivalent to {:.2} CUs / Signature", avg_time_per_verify_ns / 33.0);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100); // Adjust sample size as needed
    targets = bench_secp256r1_verify
}

fn main() {
benches();
calculate_compute();
}