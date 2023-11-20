import { BerWriter, Ber } from 'asn1';


export function uncompressedPublicKeyHex(x: string, y: string) {
  // Truncate or pad each coordinate to 32 bytes (64 hex characters)
  const xPadded = x.length > 64 ? x.slice(-64) : x.padStart(64, '0');
  const yPadded = y.length > 64 ? y.slice(-64) : y.padStart(64, '0');
  // Concatenate the '04' prefix with the padded coordinates
  return '04' + xPadded + yPadded;
}

export function derFromRS(rHex: string, sHex: string) {
  const rBuffer = Buffer.from(rHex, 'hex');
  const sBuffer = Buffer.from(sHex, 'hex');

  // Ensure that the first byte of each integer is positive. If the first byte is >= 0x80,
  // prepend a 0x00 byte to denote that the integer is positive.
  const r = (rBuffer[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), rBuffer]) : rBuffer;
  const s = (sBuffer[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), sBuffer]) : sBuffer;

  // Construct the DER encoded signature: 0x30 || totalLength || 0x02 || rLength || r || 0x02 || sLength || s
  const totalLength = 2 + r.length + 2 + s.length;
  const derEncoded = Buffer.concat([
      Buffer.from([0x30]),           // DER sequence
      Buffer.from([totalLength]),    // Total length
      Buffer.from([0x02]),           // Integer identifier
      Buffer.from([r.length]),       // Length of r
      r,                             // r value
      Buffer.from([0x02]),           // Integer identifier
      Buffer.from([s.length]),       // Length of s
      s                              // s value
  ]);

  return derEncoded.toString('hex');
}

/**
 * Creates a public key in PEM format from the x and y coordinates of a public key.
 * @param x The x coordinate of the public key in hex format.
 * @param y The y coordinate of the public key in hex format.
 * @returns 
 */
export function createPublicKeyPem(x: string, y: string): string {

  const publicKeyBuffer = Buffer.from(uncompressedPublicKeyHex(x, y), 'hex');

  const writer = new BerWriter();

  writer.startSequence();
    writer.startSequence();
      writer.writeOID('1.2.840.10045.2.1', Ber.OID); // ecPublicKey OID
      writer.writeOID('1.2.840.10045.3.1.7', Ber.OID); // prime256v1 OID
    writer.endSequence();
    // Write the public key as a BitString, including the unused bits byte
    writer.writeBuffer(Buffer.concat([Buffer.from([0x00]), publicKeyBuffer]), Ber.BitString);
  writer.endSequence();

  const derBuffer = writer.buffer;
  const pem = `-----BEGIN PUBLIC KEY-----\n${derBuffer.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;

  return pem;
}


