import crypto from "crypto";
import fs from "fs";


const VECTORAMOUNT = 2000;

// Generate random signatures for benchmarking gas usage.
// Representative of real-world usage.
// In addition, all of these should pass our crypto.subtle validation
async function main() {
  const vectors = [];

  // We want to create 1000 valid vectors
  while (vectors.length < VECTORAMOUNT) {

    // Set curve parameters and hashing algorithm
    const p256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

    // Create random private key
    const key = await crypto.subtle.generateKey(p256, true, ["sign", "verify"]);

    // Export key in DER format
    const pubKeyDer = await crypto.subtle.exportKey("spki", key.publicKey);

    // Export DER formatted key as hex-string
    const pubKeyHex = Buffer.from(pubKeyDer).toString("hex");

    // Generate message
    const msg: string = `deadbeef${vectors.length
      .toString(16)
      .padStart(4, "0")}`;

    // Generate message bytes
    // Note: The string is interpreted in hex for whatever reason?
    // I guess "utf-8" is for normies these days...
    // This small but crucial nuance sent me on a 2 hour bug-hunt cuz
    // I though my verify function was broken, smh
    const msgBuf = Buffer.from(msg, "hex");

    // Hash message bytes
    const msgHash = Buffer.from(await crypto.subtle.digest("SHA-256", msgBuf));

    // Create p256 signature over message
    const sigRaw = await crypto.subtle.sign(p256, key.privateKey, msgBuf);

    // Grab x and y coordinates from our hex-string pubkey
    const pubKey = Buffer.from(pubKeyHex.substring(54), "hex");

    // Assert length for sanity
    assert(pubKey.length === 64, "pubkey must be 64 bytes");
    const x = `${pubKey.subarray(0, 32).toString("hex")}`;
    const y = `${pubKey.subarray(32).toString("hex")}`;

    // Grab r and s from our signature
    const r = Buffer.from(sigRaw).subarray(0, 32).toString("hex");
    const s = Buffer.from(sigRaw).subarray(32, 64).toString("hex");



    // Add vector to our array
    vectors.push({
      der: "",
      x,
      y,
      r,
      s,
      hash: msgHash.toString("hex"),
      valid: true,
      msg,
      comment: `generation ${vectors.length}`,
    });
  }

  // Write all vectors to JSON
  const filepath = "./test_vectors/vectors_random_valid.jsonl";
  const lines = vectors.map((v) => JSON.stringify(v));
  fs.writeFileSync(filepath, lines.join("\n"));
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

main()
  .then(() => console.log(`Successfully generated ${VECTORAMOUNT} valid vectors ✅`))
  .catch((err) => console.error(err));
