use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Write, self};
use std::path::Path;
use std::fs::create_dir_all;
use crate::utils::format_secp256r1_vector::TestVector;

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    pub total_vectors: usize,
    pub incorrect_count: usize,
    pub incorrect_vectors: Vec<TestVector>,
}

impl Report {
    pub fn new() -> Report {
        Report {
            total_vectors: 0,
            incorrect_count: 0,
            incorrect_vectors: Vec::new(),
        }
    }

    pub fn add_incorrect_vector(&mut self, vector: TestVector) {
        self.incorrect_count += 1;
        self.incorrect_vectors.push(vector);
    }
}

pub fn write_report_to_file(file_path: &str, report: &Report) -> io::Result<()> {
    let path = Path::new(file_path);
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(report)?;
    File::create(file_path)?.write_all(json.as_bytes())?;

    Ok(())
}