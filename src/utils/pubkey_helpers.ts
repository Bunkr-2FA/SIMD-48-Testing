

/**
 * Creates properly formatted uncompressed pubkey from ```x``` and ```y``` coordinates
 * @param x x-coordinate of pubkey as hex-string
 * @param y y-coordinate of pubkey as hex-string
 * @returns Uncompressed pubkey as hex-string
 */
export function uncompressedPublicKeyHex(x: string, y: string): string {
  // Truncate or pad each coordinate to 32 bytes (64 hex characters)
  const xPadded = x.length > 64 ? x.slice(-64) : x.padStart(64, '0');
  const yPadded = y.length > 64 ? y.slice(-64) : y.padStart(64, '0');
  // Concatenate the '04' prefix with the padded coordinates
  return '04' + xPadded + yPadded;
}

/**
 * Creates DER formatted signature from ```r``` and ```s``` values
 * @param rHex r component as hex-string
 * @param sHex s component as hex-string
 * @returns DER signature in hex-string
 */
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



