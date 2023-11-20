/**
 * Represents a cryptographic vector with components for elliptic curve cryptography.
 * 
 * Properties:
 * - `x`: The 'x' coordinate of the elliptic curve point, hex-encoded.
 * - `y`: The 'y' coordinate of the elliptic curve point, hex-encoded.
 * - `sig`: The signature in DER format, hex-encoded.
 * - `msg`: The original message to be signed or verified.
 * - `valid`: Indicates whether the vector represents a valid signature.
 */
export interface Vector {
  /** The 'x' coordinate of the elliptic curve point, hex-encoded. */
  x: string;

  /** The 'y' coordinate of the elliptic curve point, hex-encoded. */
  y: string;

  r: string;
  
  s: string;

  /** The original message to be signed or verified. */
  msg: string;

  /** Indicates whether the vector represents a valid signature. */
  valid: boolean;
}
