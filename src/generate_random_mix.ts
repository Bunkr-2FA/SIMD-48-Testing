import crypto from "crypto";
import fs from "fs";

const VECTORAMOUNT = 10000;
const INVALID_SIGNATURE_PROBABILITY = 0.5; // 50% chance to generate an invalid signature

async function main() {
    const vectors = [];

    while (vectors.length < VECTORAMOUNT) {
        const p256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
        const key = await crypto.subtle.generateKey(p256, true, ["sign", "verify"]);

        const pubKeyDer = await crypto.subtle.exportKey("spki", key.publicKey);
        const pubKeyHex = Buffer.from(pubKeyDer).toString("hex");

        const msg: string = `deadbeef${vectors.length.toString(16).padStart(4, "0")}`;
        const msgBuf = Buffer.from(msg, "hex");
        const msgHash = Buffer.from(await crypto.subtle.digest("SHA-256", msgBuf));

        let sigRaw = await crypto.subtle.sign(p256, key.privateKey, msgBuf);

        // Randomly decide if this signature should be valid or invalid
        const isValid = Math.random() > INVALID_SIGNATURE_PROBABILITY;

        if (!isValid) {
            // Invalidate the signature by modifying it
            let sigBuf = Buffer.from(sigRaw);
            sigBuf[0] = (sigBuf[0] + 1) % 256; // Example modification
            sigRaw = sigBuf;
        }

        const pubKey = Buffer.from(pubKeyHex.substring(54), "hex");
        assert(pubKey.length === 64, "pubkey must be 64 bytes");
        const x = pubKey.subarray(0, 32).toString("hex");
        const y = pubKey.subarray(32).toString("hex");

        const r = Buffer.from(sigRaw).subarray(0, 32).toString("hex");
        const s = Buffer.from(sigRaw).subarray(32, 64).toString("hex");

        vectors.push({
            der: "",
            x,
            y,
            r,
            s,
            hash: msgHash.toString("hex"),
            valid: isValid,
            msg,
            comment: isValid ? `generation ${vectors.length}` : `generation ${vectors.length} (invalid)`,
        });
    }

    const filepath = "./test_vectors/vectors_random_mixed.jsonl";
    const lines = vectors.map((v) => JSON.stringify(v));
    fs.writeFileSync(filepath, lines.join("\n"));
}

function assert(cond: boolean, msg: string) {
    if (!cond) throw new Error(msg);
}

main()
    .then(() => console.log(`Successfully generated ${VECTORAMOUNT} mixed validity vectors ✅`))
    .catch((err) => console.error(err));
