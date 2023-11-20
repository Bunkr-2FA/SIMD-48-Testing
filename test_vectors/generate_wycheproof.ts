import fetch from "cross-fetch";
import fs from "fs";

//File taken from daimo's p256 verifier implementation, but slightly adjusted to include the newer v1
//test vectors from wycheproof

const wycheproofURL =
  "https://raw.githubusercontent.com/google/wycheproof/master/testvectors";
const sourceURLs = [
  `${wycheproofURL}_v1/ecdsa_secp256r1_sha256_p1363_test.json`, // new v1 vectors
  `${wycheproofURL}_v1/ecdsa_secp256r1_sha256_test.json`, // new v1 vectors
  `${wycheproofURL}/ecdsa_secp256r1_sha256_p1363_test.json`,
  `${wycheproofURL}/ecdsa_secp256r1_sha256_test.json`,
  `${wycheproofURL}/ecdsa_test.json`,
  `${wycheproofURL}/ecdsa_webcrypto_test.json`,
];

// Collect secp256r1 signature test vectors, deduplicate, and output as a single
// file. Only include vectors relevant to EIP-7212: (x,y,r,s,hash) all 256 bits.
async function main() {
  // Download latest Wycheproof vectors
  const vectors = [];
  for (const url of sourceURLs) {
    console.log(`Downloading ${url}`);
    const sourceObj = await fetch(url).then((res) => res.json());
    const friendlyName = url.replace(wycheproofURL, `wycheproof`);
    const vecs = await extractVectors(friendlyName, sourceObj);
    console.log(`Extracted ${vecs.length} vectors`);
    vectors.push(...vecs);
  }

  // Deduplicate
  console.log(`Total: ${vectors.length} vecs from ${sourceURLs.length} files`);
  const deduped = [];
  const seen = new Set();
  for (const v of vectors) {
    const key = `${v.x},${v.y},${v.r},${v.s},${v.hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(v);
  }
  console.log(`Deduped: ${deduped.length} vecs`);

  // Write to JSON
  const filepath = "./test_vectors/vectors_wycheproof.jsonl";
  console.log(`Writing ${deduped.length} vectors to ${filepath}`);
  const lines = vectors.map((v) => JSON.stringify(v));
  fs.writeFileSync(filepath, lines.join("\n"));
}

async function extractVectors(sourceName: string, sourceObj: any) {
  const vectors = [];
  for (const group of sourceObj.testGroups) {
    let type_, publicKey_, sha_;
    console.log(`${sourceName} ${sourceName.includes("v1")}`);
    
    //v1 and v0 have different key schemas, so here we have to differentiate between them
    // v1 -> publicKey ; v0 -> key
    if (sourceName.includes("v1")) {
      const {type, publicKey, sha} = group;
      type_ = type;
      publicKey_ = publicKey;
      sha_ = sha;
    }
    else {
      const {type, key, sha} = group;
      type_ = type;
      publicKey_ = key;
      sha_ = sha;
    }
    //const { type, publicKey_, sha } = group;
    if (publicKey_.curve !== "secp256r1") {
      console.log(`Skipping unsupported curve ${type_} ${publicKey_.curve}`);
      continue;
    }
    if (sha_ !== "SHA-256") {
      console.log(`Skipping unsupported hash ${type_} ${sha_}`);
      continue;
    }

    // Parse key point w
    const x = publicKey_.wx.length === 66 ? publicKey_.wx.substring(2) : publicKey_.wx;
    const y = publicKey_.wy.length === 66 ? publicKey_.wy.substring(2) : publicKey_.wy;

    for (const test of group.tests) {
      const { tcId, comment, msg, sig, result } = test;
      const testStr = `${sourceName} ${type_} ${sha_} #${tcId}`;

      // Wycheproof uses two signature encodings: ASN.1 and P1363
      const isASN = type_ === "EcdsaVerify";
      const isP1363 = type_ === "EcdsaP1363Verify";
      assert(isASN || isP1363, type_);

      // Many Wycheproof vectors are not actually testing P256, but rather the
      // ASN decoding. We only want the P256 vectors.
      let r, s;
      try {
        if (isASN) [r, s] = tryParseASN(sig);
        else[r, s] = tryParseP1363(sig);
      } catch (e: any) {
        console.warn(`Skipping bad sig ${testStr}: ${e.message} ${comment}`);
        continue;
      }

      assert(["valid", "invalid", "acceptable"].includes(result), result);

      // "acceptable" means Wycheproof doesn't say either result is mandatory.
      // We have two "acceptable" vectors, both valid according to SubtleCrypto.
      const valid = result === "valid" || result === "acceptable";
      

      // calculate SHA256 hash of msgBytes
      const msgBytes = Buffer.from(msg, "hex");
      const msgHash = Buffer.from(await crypto.subtle.digest(sha_, msgBytes));
      assert(msgHash.length === 32, "hash must be 256 bits");

      vectors.push({
        x: x.padStart(64, "0"),
        y: y.padStart(64, "0"),
        r: r.padStart(64, "0"),
        s: s.padStart(64, "0"),
        hash: msgHash.toString("hex"),
        valid,
        msg,
        comment: `${testStr}: ${comment}`,
        result,
      });
    }
  }
  return vectors;
}

// Parse r,s from an ASN.1-encoded signature
export function tryParseASN(sig: string): [string, string] {
  let r, rLen, s, sLen, totalLen;
  let rem = consume(sig, "30"); // SEQUENCE
  [totalLen, rem] = read(rem, 2); // length, verified at the end
  assert(parseInt(totalLen, 16) === sig.length / 2 - 2, "wrong total length");

  rem = consume(rem, "02"); // INTEGER
  [rLen, rem] = read(rem, 2);
  if (rLen === "21") rem = consume(rem, "00");
  else assert(rLen === "20", `exp 20 or 21, found ${rLen}`);
  [r, rem] = read(rem, 64);

  rem = consume(rem, "02"); // INTEGER
  [sLen, rem] = read(rem, 2);
  if (sLen === "21") rem = consume(rem, "00");
  else assert(sLen === "20", `exp 20 or 21, found ${sLen}`);
  [s, rem] = read(rem, 64);
  assert(rem === "", "extra trailing bytes");

  return [r, s];
}

// Parse r,s from an P1363-encoded signature
function tryParseP1363(sig: string): [string, string] {
  assert(sig.length === 128, `exp 128 chars, found ${sig.length}`);
  const r = sig.substring(0, 64);
  const s = sig.substring(64);
  return [r, s];
}

function consume(str: string, prefix: string) {
  if (!str.startsWith(prefix)) {
    throw new Error(`exp ${prefix}, found ${str.substring(0, prefix.length)}`);
  }
  return str.substring(prefix.length);
}

function read(str: string, n: number) {
  assert(str.length >= n, `exp ${n} chars, found ${str.length}`);
  return [str.substring(0, n), str.substring(n)];
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

main()
  .then(() => console.log("Done"))
  .catch((err) => console.error(err));
