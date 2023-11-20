import crypto from "crypto";
import fs from "fs";
import {verifyVector} from '../src/utils/crypto_check_vector'

// Generate random signatures for benchmarking gas usage.
// Representative of real-world usage.
async function main() {
  const vectors = [];

  while (vectors.length < 1000) {
    console.log(`Generating vector ${vectors.length}`);
    const p256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
    const key = await crypto.subtle.generateKey(p256, true, ["sign", "verify"]);
    const pubKeyDer = await crypto.subtle.exportKey("spki", key.publicKey);
    const pubKeyHex = Buffer.from(pubKeyDer).toString("hex");
    // console.log(`Generated pubkey: ${pubKeyHex}`);

    const msg: string = `deadbeef${vectors.length
      .toString(16)
      .padStart(4, "0")}`;
    const msgBuf = Buffer.from(msg, "hex");
    const msgHash = Buffer.from(await crypto.subtle.digest("SHA-256", msgBuf));
    const sigRaw = await crypto.subtle.sign(p256, key.privateKey, msgBuf);
    
    const pubKey = Buffer.from(pubKeyHex.substring(54), "hex");
    assert(pubKey.length === 64, "pubkey must be 64 bytes");
    const x = `${pubKey.subarray(0, 32).toString("hex")}`;
    const y = `${pubKey.subarray(32).toString("hex")}`;

    const r = Buffer.from(sigRaw).subarray(0, 32).toString("hex");
    const s = Buffer.from(sigRaw).subarray(32, 64).toString("hex");

    
    // const isValid = await crypto.subtle.verify(
    //   p256,
    //   key.publicKey,
    //   sigRaw,
    //   msgBuf
    // );
    const vector = {
      x: x,
      y: y,
      r: r,
      s: s,
      sig: "",
      msg: msg,
      valid: true
    };
    //console.log(`Generated vector: ${JSON.stringify(vector, undefined, 2)}`);
    const isValid = await verifyVector(
      {
        x: x,
        y: y,
        r: r,
        s: s,
        msg: msg,
        valid: true
      }
    );
    assert(isValid, "Signature verification failed");

    vectors.push({
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

  // Write to JSON
  const filepath = "./test_vectors/vectors_random_valid.jsonl";
  console.log(`Writing ${vectors.length} vectors to ${filepath}`);
  const lines = vectors.map((v) => JSON.stringify(v));
  fs.writeFileSync(filepath, lines.join("\n"));
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

main()
  .then(() => console.log("Done"))
  .catch((err) => console.error(err));
