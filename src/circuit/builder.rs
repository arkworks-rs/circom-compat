use ark_ec::PairingEngine;
use std::{fs::File, path::Path};

use super::{CircomCircuit, R1CS};

use num_bigint::BigInt;
use std::collections::HashMap;

use crate::{circuit::R1CSFile, WitnessCalculator};
use color_eyre::Result;

pub struct CircomBuilder<E: PairingEngine> {
    pub cfg: CircuitConfig<E>,
    pub inputs: HashMap<String, Vec<BigInt>>,
}

// Add utils for creating this from files / directly from bytes
pub struct CircuitConfig<E: PairingEngine> {
    pub r1cs: R1CS<E>,
    pub wtns: WitnessCalculator,
    pub sanity_check: bool,
}

impl<E: PairingEngine> CircuitConfig<E> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let wtns = WitnessCalculator::new(wtns).unwrap();
        let reader = File::open(r1cs)?;
        let r1cs = R1CSFile::new(reader)?.into();
        Ok(Self {
            wtns,
            r1cs,
            sanity_check: false,
        })
    }
}

impl<E: PairingEngine> CircomBuilder<E> {
    /// Instantiates a new builder using the provided WitnessGenerator and R1CS files
    /// for your circuit
    pub fn new(cfg: CircuitConfig<E>) -> Self {
        Self {
            cfg,
            inputs: HashMap::new(),
        }
    }

    /// Pushes a Circom input at the specified name.
    pub fn push_input<T: Into<BigInt>>(&mut self, name: impl ToString, val: T) {
        let values = self.inputs.entry(name.to_string()).or_insert_with(Vec::new);
        values.push(val.into());
    }

    /// Generates an empty circom circuit with no witness set, to be used for
    /// generation of the trusted setup parameters
    pub fn setup(&self) -> CircomCircuit<E> {
        let mut circom = CircomCircuit {
            r1cs: self.cfg.r1cs.clone(),
            witness: None,
        };

        // Disable the wire mapping
        circom.r1cs.wire_mapping = None;

        circom
    }

    /// Creates the circuit populated with the witness corresponding to the previously
    /// provided inputs
    pub fn build(mut self) -> Result<CircomCircuit<E>> {
        let mut circom = self.setup();

        // calculate the witness
        let witness = self
            .cfg
            .wtns
            .calculate_witness(self.inputs, self.cfg.sanity_check)?;

        // convert it to field elements
        let witness = witness
            .into_iter()
            .map(|w| E::Fr::from(w.to_biguint().unwrap()))
            .collect::<Vec<_>>();
        circom.witness = Some(witness);

        // sanity check
        debug_assert!({
            use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
            let cs = ConstraintSystem::<E::Fr>::new_ref();
            circom.clone().generate_constraints(cs.clone()).unwrap();
            cs.is_satisfied().unwrap()
        });

        Ok(circom)
    }
}
