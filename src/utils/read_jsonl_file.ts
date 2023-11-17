import fs from 'fs';
import {Vector} from '../types/vector'

// Function to parse each line and extract the desired fields
function parseJsonLine(line: string) {
    try {
      const data = JSON.parse(line);
      const { x, y, r, s, msg, hash, valid } = data;
      return { x, y, r, s, msg, hash, valid };
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
            vectors.push(parsedData);
          }
        }
  
        buffer = lines[lines.length - 1];
      });
  
      readStream.on('end', () => {
        if (buffer.trim().length > 0) {
          const parsedData = parseJsonLine(buffer);
          if (parsedData) {
            vectors.push(parsedData);
          }
        }
  
        resolve(vectors); // Resolve the Promise with the vectors array when reading is complete
      });
  
      readStream.on('error', (error) => {
        reject(error); // Reject the Promise if there's an error during reading
      });
    });
  }