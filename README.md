# <h1 align="center"> ark-circom </h1>

Arkworks bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.

![Github Actions](https://github.com/gakonst/ark-circom/workflows/Tests/badge.svg)

## Documentation

Clone the repository and run `cd ark-circom/ && cargo doc --open`

## Add ark-circom to your repository

```toml
[dependencies]

ark-circom = { git = "https://github.com/gakonst/ark-circom-rs" }
```

## Running the tests

Tests require the following installed:
1. [`solc`](https://solidity.readthedocs.io/en/latest/installing-solidity.html). We also recommend using [solc-select](https://github.com/crytic/solc-select) for more flexibility.
2. [`ganache-cli`](https://github.com/trufflesuite/ganache-cli#installation)

## Features

- [x] Witness generation using Circom's WASM witness code
- [x] ZKey parsing into Arkworks Proving Key over BN254
- [x] Compatibility layer for Ethereum types, so that proofs can be used in Solidity verifiers
- [x] Proof generations and verification using Arkworks
- [ ] CLI for common operations

## Acknowledgements

This library would not have been possibly without the great work done in:
- [`zkutil`](https://github.com/poma/zkutil/)
- [`snarkjs`](https://github.com/iden3/snarkjs/)

Special shoutout to [Kobi Gurkan](https://github.com/kobigurk/) for all the help in parsing SnarkJS' ZKey file format.
