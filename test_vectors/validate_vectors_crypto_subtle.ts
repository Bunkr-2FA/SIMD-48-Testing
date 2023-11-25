
import { readJsonLFile } from '../src/utils/read_jsonl_file';
import { Vector } from '../src/types/vector';
import { verifyVector } from '../src/utils/verify_vector_crypto_subtle';


// Define the path to JSONL files
const filePaths = [
    'test_vectors/vectors_wycheproof.jsonl',
    'test_vectors/vectors_random_valid.jsonl'
];


async function main() {
    try {
        const vectors: Vector[] = [];

        // For every file in filePaths, parse and push the respective vectors into vectors
        for (const filePath of filePaths) {
            const fileVectors = await readJsonLFile(filePath);
            vectors.push(...fileVectors);
        }
        // Instantiate variables to track total vectors as well as mismatched vectors
        let countMismatch = 0;
        let count = 0;

        // Iterate through each vector and validate it with verifyVector
        // The idea here is to confirm that crypto.subtle has parity with the results
        // from the wycheproof project
        for (const vector of vectors) {
            count++;
            const checkValid = await verifyVector(vector);

            // If the "should" restult of the vector doesn't match with our actual result,
            // increment count and log
            if (checkValid !== vector.valid) {
                console.log(count)
                console.log(`Vector ${JSON.stringify(vector, undefined, 2)} does not match`);
                countMismatch++;
            }

        }

        // Log the total number of vectors as well and the amount of mismatched ones
        console.log(`Total number of vectors: ${vectors.length}`);
        console.log(`Total number of mismatched vectors: ${countMismatch}`);

    } catch (error) {
        console.error(`Error reading the file: ${error}`);
    }
}

main();
