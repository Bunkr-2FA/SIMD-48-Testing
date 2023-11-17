# Testing & Fuzzing of the `secp256r1` program implementation on Solana

## Introduction

This repository is focused on the testing and fuzzing of the `secp256r1` implementation found in [SIMD-0048](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0048-native-program-for-secp256r1-sigverify.md).

## Purpose

The aim is to ensure the robustness and security of `secp256r1` implementation by providing comprehensive tests from the wycheproof project as well as some fuzzing strategies.

## Contents

- `src`: Source code for the test suite.
- `test_vectors`: Test vector generation and validation for `secp256r1` usage.
- `secp256r1_verify`: SIMD-0048 implementation of the `secp256r1` precompile.

## Getting Started

1. Clone the repository: `git clone https://github.com/Bunkr-2FA/SIMD-48-Testing`
2. Install dependencies: `npm install`
3. Run tests: `npm test`

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License

This project is licensed under the [LICENSE] - see the LICENSE file for details.
