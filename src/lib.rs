//! Arkworks - Circom Compatibility layer
//!
//! Given a Circom WASM-compiled witness.wasm, it can read it and calculate the corresponding
//!
//! ## WASM Witness Generator
//!
//! ## Types
//! * ZKey
//! * WTNS
//! * R1CS
//! * WASM
//! * Sys?
//!
//! Inputs:
//! * circuit.wasm
//! * input.json
//!
//! Outputs:
//! * witness.wtns
//!
//! Given a circuit WASM and an input.json calculates the corresponding witness
//!
//! ## Proof calculator
//!
//! Inputs:
//! * witness.wtns / witness.json
//! * circuit.zkey
//!
//! Given a witness (and r1cs?) synthesizes the circom circuit
//! And then feeds it to the arkworks groth16 prover
//!
//! Outputs:
//! * public.json
//! * proof.json
//!
//! ## Smart Contract connector class
//!
//! Given an Arkworks proof, it's able to translate it to the Circom-verifier
//! expected arguments
//!
//! (No Dark Forest specific modifications included, these are part of df-snark)
//!
//! ## Binary
//!
//! CLIs for each of the above + logging to stdout
//!
//! witness for the specified inputs
//!
//! ## Commands
//!
//! Compile a circuit:
//! `circom circuit.circom --r1cs --wasm --sym`
//!
//! Phase2 over circuit + PoT
//! `snarkjs zkey new circuit.r1cs powersOfTau28_hez_final_10.ptau circuit_0000.zkey`
//! `snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey`
//! `snarkjs zkey export verificationkey circuit_final.zkey verification_key.json`
//!
//! Witness calculation from inputs:
//! `snarkjs wtns calculate circuit.wasm input.json witness.wtns`
//! `snarkjs wtns export json witness.wtns witness.json`
//!
//! Groth16 proof calculation:
//! `snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json`
//!
//! Groth16 Proof verification:
//! `snarkjs groth16 verify verification_key.json public.json proof.json`

mod circom_wasm;
pub use circom_wasm::WitnessCalculator;

pub mod circuit;
pub use circuit::{CircomBuilder, CircomCircuit, CircuitConfig};

pub mod ethereum;

pub mod zkey;

pub mod circom_qap;
