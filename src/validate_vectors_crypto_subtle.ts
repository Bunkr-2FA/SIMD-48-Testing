import fs from 'fs';
import { readJsonLFile } from './utils/read_jsonl_file';
import { Vector } from './types/vector';
import { verifyVector } from './utils/verify_vector_crypto_subtle';

// Define the path to JSONL files
const filePaths = [
    'test_vectors/vectors_wycheproof.jsonl',
    'test_vectors/vectors_random_valid.jsonl',
    'test_vectors/vectors_random_mixed.jsonl',
];

async function main() {
    try {
        const vectors: Vector[] = [];
        let mismatchedVectors: Vector[] = [];
        let countMismatch = 0;
        let count = 0;

        for (const filePath of filePaths) {
            const fileVectors = await readJsonLFile(filePath);
            vectors.push(...fileVectors);
        }

        for (const vector of vectors) {
            count++;
            const checkValid = await verifyVector(vector);
            if (checkValid !== vector.valid) {
                // console.log(`Mismatch at count: ${count}`);
                // console.log(`Vector ${JSON.stringify(vector, undefined, 2)} does not match`);
                mismatchedVectors.push(vector);
                countMismatch++;
            }
        }

        // Generate report
        const report = {
            totalVectors: vectors.length,
            mismatchedCount: countMismatch,
            mismatchedVectors
        };

        // Write report to file
        fs.writeFileSync('Reports/subtlecrypto_report.json', JSON.stringify(report, null, 2));

        console.log('SubtleCrypo Report generated ✅');
        console.log(`Total number of vectors: ${vectors.length}`);
        console.log(`Total number of mismatched vectors: ${countMismatch}\n`);

    } catch (error) {
        console.error(`Error processing the file: ${error}`);
    }
}

main();
