use ark_ec::PairingEngine;

pub mod r1cs_reader;
pub use r1cs_reader::{R1CSFile, R1CS};

mod circom;
pub use circom::CircomCircuit;

mod builder;
pub use builder::{CircomBuilder, CircuitConfig};

pub type Constraints<E> = (ConstraintVec<E>, ConstraintVec<E>, ConstraintVec<E>);
pub type ConstraintVec<E> = Vec<(usize, <E as PairingEngine>::Fr)>;
