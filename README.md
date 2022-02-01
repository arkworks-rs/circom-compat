# <h1 align="center"> ark-circom </h1>

Arkworks bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.

![Github Actions](https://github.com/gakonst/ark-circom/workflows/Tests/badge.svg)

## Documentation

Clone the repository and run `cd ark-circom/ && cargo doc --open`

## Add ark-circom to your repository

```toml
[dependencies]

ark-circom = { git = "https://github.com/gakonst/ark-circom.git" }
```

## Example

```rust
// Load the WASM and R1CS for witness and proof generation
let cfg = CircomConfig::<Bn254>::new(
    "./test-vectors/mycircuit.wasm",
    "./test-vectors/mycircuit.r1cs",
)?;

// Insert our public inputs as key value pairs
let mut builder = CircomBuilder::new(cfg);
builder.push_input("a", 3);
builder.push_input("b", 11);

// Create an empty instance for setting it up
let circom = builder.setup();

// Run a trusted setup
let mut rng = thread_rng();
let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

// Get the populated instance of the circuit with the witness
let circom = builder.build()?;

let inputs = circom.get_public_inputs().unwrap();

// Generate the proof
let proof = prove(circom, &params, &mut rng)?;

// Check that the proof is valid
let pvk = prepare_verifying_key(&params.vk);
let verified = verify_proof(&pvk, &proof, &inputs)?;
assert!(verified);
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
