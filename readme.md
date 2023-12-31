# Testing & Fuzzing of the `secp256r1` program implementation on Solana

## Introduction

This repository is focused on the testing and fuzzing of the `secp256r1` implementation found in [SIMD-0048](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0048-native-program-for-secp256r1-sigverify.md).

## Purpose

The aim is to ensure the robustness and security of `secp256r1` implementation
by providing comprehensive tests from the wycheproof project as well as some
fuzzing strategies.
Additionally all test vectors are run against a SubleCrypto implementation
as well as an OpenSSL implementation to ensure parity between the three.

## Contents

- `src`: Contains the source code for generating, fetching and validating vectors
  using SubtleCrypto (an API standardized by W3C)
- `test_vectors`: Files containing test vectors to be validated against
- `secp256r1_verify/src`: SIMD-0048 implementation of the `secp256r1` precompile
  as well as the OpenSSL verification implementation.
- `Reports`: Contains the latest reports of each implementation
  against the test vectors found in `test_vectors`

## Getting Started

1. Clone the repository: `git clone https://github.com/Bunkr-2FA/SIMD-48-Testing`
2. Install dependencies: `npm install`
3. (Optional) Run the following command to re-fetch and generate new vectors:
   `npm run generate_vectors`
4. Generate reports for SubtleCrypto, OpenSSL and p256: `npm run generate_reports`
5. Run benchmark against vectors: `npm run benchmark`

## Wycheproof Vectors

The vectors provided by Project Wycheproof consist of a pubkey with
`wx` and `wy`representing the coordinates,
`sig` a DER encoded signature and `message`, the corresponding message.

```json
"testGroups" : [
    {
      "key" : {
        "curve" : "secp256r1",
        "keySize" : 256,
        "type" : "EcPublicKey",
        "uncompressed" : "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "wx" : "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "wy" : "00c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"
      },
      "keyDer" : "3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60
      f4606766b3d9685001558d1a974e7341513e",
      "keyPem" : "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKSexBRK64+3c/kZ4KBKLrSkDJpkZ\n9whgac
      jE32xzKDjHeHlk6qwA5ZIfsUmKYPRgZ2az2WhQAVWNGpdOc0FRPg==\n-----END PUBLIC KEY-----",
      "sha" : "SHA-256",
      "type" : "EcdsaVerify",
      "tests" :
        {
          "tcId" : 1,
          "comment" : "signature malleability",
          "msg" : "313233343030",
          "sig" : "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1802204cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
          "result" : "valid",
          "flags" : []
        }
    }]
```

Some of the signatures are purposely disfigured
to test the ASN.1 decoding process of certain crypto implementations.
In the case of SIMD-48, the precompile only accepts a compressed pubkey and
a serialized signature consisting of the concatenated `r` and `s` values.
This means that no signature decoding happens inside the precompile.
As those vector's signatures are disfigured, it's not possible to correctly
extract `r` and `s` from them. Therefore these vectors are ignored.

Note: There is however a legacy vector that gets successfully parsed by the
ASN.1 decoding found in `src/generate_wycheproof.ts`. The vector's
signature is missing a 0 in it's `s` component. The behavior of the vector is
described by Project Wycheproof:

```json
"MissingZero" : {
     "bugType" : "LEGACY",
     "description" : "Some implementations of ECDSA and DSA incorrectly
      encode r and s by not including leading zeros in the ASN encoding of
      integers when necessary. Hence, some implementations (e.g. jdk) allow
       signatures with incorrect ASN encodings assuming that the signature
       is otherwise valid.",
     "effect" : "While signatures are more malleable if such signatures are
     accepted, this typically leads to no vulnerability, since a badly
      encoded signature can be reencoded correctly."
   }
```

The following vector registers as `valid` in all 3 implementations. This is a result
of the ASN.1 client-side decoding adding the missing 0 during parsing and therefore
making the vector valid.

```json
{
	"tcId": 6,
	"comment": "Legacy: ASN encoding of s misses leading 0",
	"flags": ["MissingZero"],
	"msg": "313233343030",
	"sig": "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"result": "invalid"
}
```

## Reports

The reports are generated by the validation scripts that run the test vectors
agains the different implementations

P256:

```json
{
  "total_vectors": 13202,
  "incorrect_count": 1,
  "incorrect_vectors": [
    {
      "der": "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "x": "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
      "y": "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
      "r": "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
      "s": "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "hash": "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
      "valid": false,
      "msg": "313233343030",
      "comment": "wycheproof_v1/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256
       #6: Legacy: ASN encoding of s misses leading 0"
    }
  ]
}
```

SubtleCrypto:

```json
{
  "totalVectors": 13202,
  "mismatchedCount": 1,
  "mismatchedVectors": [
    {
      "der": "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "x": "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
      "y": "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
      "r": "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
      "s": "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "msg": "313233343030",
      "valid": false,
      "comment": "wycheproof_v1/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256
       #6: Legacy: ASN encoding of s misses leading 0"
    }
  ]
}
```

OpenSSL:

```json
{
  "total_vectors": 13202,
  "incorrect_count": 1,
  "incorrect_vectors": [
    {
      "der": "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "x": "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
      "y": "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
      "r": "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
      "s": "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
      "hash": "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
      "valid": false,
      "msg": "313233343030",
      "comment": "wycheproof_v1/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256
       #6: Legacy: ASN encoding of s misses leading 0"
    }
  ]
}
```

As shown above, all 3 implementation have parity across 13202 test vectors and
exhibit the mismatch mentioned in [Wycheproof Vectors](#wycheproof-vectors).

Note: Of the 13202 vectors, 1202 come from Project Wycheproof.

## Benchmarking

The following benchmark was run on a 16GB M1 Pro Macbook Pro.

![benchmark](/images/M1%20Pro%20Benchmark.png)
