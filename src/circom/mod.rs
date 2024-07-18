pub mod r1cs_reader;
pub use r1cs_reader::{R1CSFile, R1CS};

mod circuit;
pub use circuit::CircomCircuit;

mod builder;
pub use builder::{CircomBuilder, CircomConfig};

mod qap;
pub use qap::CircomReduction;

pub type Constraints<F> = (ConstraintVec<F>, ConstraintVec<F>, ConstraintVec<F>);
pub type ConstraintVec<F> = Vec<(usize, F)>;
