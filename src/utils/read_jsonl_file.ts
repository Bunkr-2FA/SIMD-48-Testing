import fs from 'fs';
import { Vector } from '../types/vector'

// Function to parse each line and extract the desired fields
function parseJsonLine(line: string) {
  try {
    const data = JSON.parse(line);
    const { der, x, y, r, s, msg, valid, comment } = data;
    return { der, x, y, r, s, msg, valid, comment };
  } catch (error) {
    console.error(`Error parsing JSON in line: ${line}`);
    return null;
  }
}

export async function readJsonLFile(filePath: string): Promise<Vector[]> {
  return new Promise<Vector[]>((resolve, reject) => {
    const vectors: Vector[] = [];
    const readStream = fs.createReadStream(filePath, { encoding: 'utf-8' });
    let buffer = '';

    readStream.on('data', (chunk: Buffer) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');

      for (let i = 0; i < lines.length - 1; i++) {
        const parsedData = parseJsonLine(lines[i]);
        if (parsedData) {
          vectors.push(
            {
              der: parsedData.der,
              x: parsedData.x,
              y: parsedData.y,
              r: parsedData.r,
              s: parsedData.s,
              msg: parsedData.msg,
              valid: parsedData.valid,
              comment: parsedData.comment
            }
          );
        }
      }

      buffer = lines[lines.length - 1];
    });

    readStream.on('end', () => {
      if (buffer.trim().length > 0) {
        const parsedData = parseJsonLine(buffer);
        if (parsedData) {
          vectors.push(
            {
              der: parsedData.der,
              x: parsedData.x,
              y: parsedData.y,
              r: parsedData.r,
              s: parsedData.s,
              msg: parsedData.msg,
              valid: parsedData.valid,
              comment: parsedData.comment
            }
          );
        }
      }

      resolve(vectors); // Resolve the Promise with the vectors array when reading is complete
    });

    readStream.on('error', (error) => {
      reject(error); // Reject the Promise if there's an error during reading
    });
  });
}