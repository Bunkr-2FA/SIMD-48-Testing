import * as fs from 'fs';
import { readJsonLFile } from '../src/utils/read_jsonl_file';
import { Vector } from '../src/types/vector';
import { verifyVector } from '../src/utils/crypto_check_vector';
import { derFromRS } from '../src/utils/create_pem_pubkey';

// Define the path to your JSONL file
const filePaths = [
    'test_vectors/vectors_wycheproof.jsonl',
    'test_vectors/vectors_random_valid.jsonl'
];
// const filePaths = [
//     'test_vectors/vectors_random_valid.jsonl'
// ];

async function main() {
    try {
        const vectors: Vector[] = [];
        for (const filePath of filePaths) {
            const fileVectors = await readJsonLFile(filePath);
            vectors.push(...fileVectors);
        }
        let count_mismatch = 0;
        let count = 0;
        for (const vector of vectors) {
            // if (vector.sig === "") {
            //     vector.sig = derFromRS(vector.r, vector.s);
            // }
            count++;
            const checkValid = await verifyVector(vector);
            if (checkValid !== vector.valid) {
                console.log(count)
                console.log(`Vector ${JSON.stringify(vector, undefined, 2)} does not match`);
                count_mismatch++;
            }

        }
        console.log(`Total number of vectors: ${vectors.length}`);
        console.log(`Total number of mismatched vectors: ${count_mismatch}`);

    } catch (error) {
        console.error(`Error reading the file: ${error}`);
    }
}

main();
