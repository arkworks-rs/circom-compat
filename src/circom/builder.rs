use super::{CircomCircuit, R1CS};
use crate::{
    circom::R1CSFile,
    witness::{Wasm, WitnessCalculator},
};
use ark_ff::PrimeField;
use color_eyre::Result;
use num_bigint::BigInt;
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::BufReader, path::Path};
use wasmer::Store;

#[derive(Debug)]
pub struct CircomBuilder<F: PrimeField> {
    pub cfg: CircomConfig<F>,
    pub inputs: HashMap<String, Vec<BigInt>>,
}

// Add utils for creating this from files / directly from bytes
#[derive(Debug)]
pub struct CircomConfig<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub wtns: WitnessCalculator,
    pub store: Store,
    pub sanity_check: bool,
}

impl<F: PrimeField> CircomConfig<F> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let mut store = Store::default();
        let wtns = WitnessCalculator::new(&mut store, wtns).unwrap();
        let reader = BufReader::new(File::open(r1cs)?);
        let r1cs = R1CSFile::new(reader)?.into();
        Ok(Self {
            wtns,
            r1cs,
            store,
            sanity_check: false,
        })
    }

    pub fn new_from_wasm(wasm: Wasm, r1cs: impl AsRef<Path>) -> Result<Self> {
        let mut store = Store::default();
        let wtns = WitnessCalculator::new_from_wasm(&mut store, wasm).unwrap();
        let reader = File::open(r1cs)?;
        let r1cs = R1CSFile::new(reader)?.into();
        Ok(Self {
            wtns,
            r1cs,
            store,
            sanity_check: false,
        })
    }
}

impl<F: PrimeField> CircomBuilder<F> {
    /// Instantiates a new builder using the provided WitnessGenerator and R1CS files
    /// for your circuit
    pub fn new(cfg: CircomConfig<F>) -> Self {
        Self {
            cfg,
            inputs: HashMap::new(),
        }
    }

    /// Pushes a Circom input at the specified name.
    pub fn push_input<T: Into<BigInt>>(&mut self, name: impl ToString, val: T) {
        let values = self.inputs.entry(name.to_string()).or_default();
        values.push(val.into());
    }
    // Loads the input.json file from the specified path
    pub fn load_input_json<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let raw: HashMap<String, BigIntOrVec> = serde_json::from_reader(reader)?;

        let parsed = raw
            .into_iter()
            .map(|(k, v)| {
                let vec = match v {
                    BigIntOrVec::Single(s) => vec![s.parse::<BigInt>()?],
                    BigIntOrVec::Vec(vs) => vs
                        .into_iter()
                        .map(|s| s.parse::<BigInt>())
                        .collect::<Result<_, _>>()?,
                };
                Ok((k, vec))
            })
            .collect::<Result<HashMap<_, _>, color_eyre::eyre::Error>>()?;

        self.inputs = parsed;
        Ok(())
    }

    /// Generates an empty circom circuit with no witness set, to be used for
    /// generation of the trusted setup parameters
    pub fn setup(&self) -> CircomCircuit<F> {
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
    pub fn build(mut self) -> Result<CircomCircuit<F>> {
        let mut circom = self.setup();

        // calculate the witness
        let witness = self.cfg.wtns.calculate_witness_element::<F, _>(
            &mut self.cfg.store,
            self.inputs,
            self.cfg.sanity_check,
        )?;
        circom.witness = Some(witness);

        // sanity check
        debug_assert!({
            use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
            let cs = ConstraintSystem::<F>::new_ref();
            circom.clone().generate_constraints(cs.clone()).unwrap();
            let is_satisfied = cs.is_satisfied().unwrap();
            if !is_satisfied {
                println!(
                    "Unsatisfied constraint: {:?}",
                    cs.which_is_unsatisfied().unwrap()
                );
            }

            is_satisfied
        });

        Ok(circom)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BigIntOrVec {
    Single(String),
    Vec(Vec<String>),
}
