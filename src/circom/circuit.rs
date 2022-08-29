use ark_ec::PairingEngine;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use super::R1CS;

use color_eyre::Result;

#[derive(Clone, Debug)]
pub struct CircomCircuit<E: PairingEngine> {
    pub r1cs: R1CS<E>,
    pub witness: Option<Vec<E::Fr>>,
}

impl<E: PairingEngine> CircomCircuit<E> {
    pub fn get_public_inputs(&self) -> Option<Vec<E::Fr>> {
        match &self.witness {
            None => None,
            Some(w) => match &self.r1cs.wire_mapping {
                None => Some(w[1..self.r1cs.num_inputs].to_vec()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i]).collect()),
            },
        }
    }
}

impl<E: PairingEngine> ConstraintSynthesizer<E::Fr> for CircomCircuit<E> {
    fn generate_constraints(self, cs: ConstraintSystemRef<E::Fr>) -> Result<(), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        // Start from 1 because Arkworks implicitly allocates One for the first input
        for i in 1..self.r1cs.num_inputs {
            cs.new_input_variable(|| {
                Ok(match witness {
                    None => E::Fr::from(1u32),
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i]],
                        None => w[i],
                    },
                })
            })?;
        }

        for i in 0..self.r1cs.num_aux {
            cs.new_witness_variable(|| {
                Ok(match witness {
                    None => E::Fr::from(1u32),
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i + self.r1cs.num_inputs]],
                        None => w[i + self.r1cs.num_inputs],
                    },
                })
            })?;
        }

        let make_index = |index| {
            if index < self.r1cs.num_inputs {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - self.r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, E::Fr)]| {
            lc_data.iter().fold(
                LinearCombination::<E::Fr>::zero(),
                |lc: LinearCombination<E::Fr>, (index, coeff)| lc + (*coeff, make_index(*index)),
            )
        };

        for constraint in &self.r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CircomBuilder, CircomConfig};
    use ark_bn254::{Bn254, Fr};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn satisfied() {
        let cfg = CircomConfig::<Bn254>::new(
            "./test-vectors/mycircuit.wasm",
            "./test-vectors/mycircuit.r1cs",
        )
        .unwrap();
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);

        let circom = builder.build().unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circom.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
