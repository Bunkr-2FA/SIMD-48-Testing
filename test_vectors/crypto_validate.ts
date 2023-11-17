import * as fs from 'fs';
import { readJsonLFile } from '../src/utils/read_jsonl_file';

interface Vector {
    x: string;
    y: string;
    r: string;
    s: string;
    msg: string;
    hash: string;
    valid: boolean;
}

// Define the path to your JSONL file
const filePaths = [
    'test_vectors/vectors_wycheproof.jsonl',
    'test_vectors/vectors_random_valid.jsonl'
];

async function main() {
    try {
        const vectors: Vector[] = [];
        for (const filePath of filePaths) {
            const fileVectors = await readJsonLFile(filePath);
            vectors.push(...fileVectors);
        }

    } catch (error) {
        console.error(`Error reading the file: ${error}`);
    }
}

main();
