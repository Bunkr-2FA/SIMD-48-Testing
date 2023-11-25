import crypto from 'crypto';
import { uncompressedPublicKeyHex } from './pubkey_helpers';
import { Vector } from '../types/vector'


const p256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

export async function verifyVector(vector: Vector): Promise<boolean> {
  const { x, y, r, s, msg } = vector;

  const publicKeyUncompressed = uncompressedPublicKeyHex(x, y);
  const pubKeyBuf = Buffer.from(publicKeyUncompressed, 'hex');
  const rBuf = Buffer.from(r, 'hex');
  const sBuf = Buffer.from(s, 'hex');
  const signatureBuf = Buffer.concat([rBuf, sBuf]);
  const publicKey = await crypto.subtle.importKey(
    'raw', // Format
    pubKeyBuf, // Key data
    {
      name: 'ECDSA',
      namedCurve: 'P-256' // e.g., 'P-256'
    },
    true, // Extractable
    ['verify'] // Key usage
  );

  const isVerified = crypto.subtle.verify(
    p256,
    publicKey,
    signatureBuf,
    Buffer.from(msg, 'hex')
  )

  return isVerified;
}


