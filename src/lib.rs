//! Arkworks - Circom Compatibility layer
//!
//! Provides bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.
mod witness;
pub use witness::WitnessCalculator;

pub mod circom;
pub use circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};

mod zkey;
pub use zkey::read_zkey;
