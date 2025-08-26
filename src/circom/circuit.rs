use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use color_eyre::Result;
use rayon::prelude::*;

use super::R1CS;

#[derive(Clone, Debug)]
pub struct CircomCircuit<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub witness: Option<Vec<F>>,
}

impl<F: PrimeField> CircomCircuit<F> {
    pub fn get_public_inputs(&self) -> Option<Vec<F>> {
        match &self.witness {
            None => None,
            Some(w) => match &self.r1cs.wire_mapping {
                None => Some(w[1..self.r1cs.num_inputs].to_vec()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i]).collect()),
            },
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CircomCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        // Start from 1 because Arkworks implicitly allocates One for the first input
        for i in 1..self.r1cs.num_inputs {
            let _ = cs.new_input_variable(|| {
                Ok(match witness {
                    None => F::ONE,
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i]],
                        None => w[i],
                    },
                })
            })?;
        }

        for i in 0..self.r1cs.num_aux {
            let _ = cs.new_witness_variable(|| {
                Ok(match witness {
                    None => F::ONE,
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i + self.r1cs.num_inputs]],
                        None => w[i + self.r1cs.num_inputs],
                    },
                })
            })?;
        }

        let make_index = |index| {
            if index < self.r1cs.num_inputs {
                Variable::instance(index)
            } else {
                Variable::witness(index - self.r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, F)]| {
            let lc = lc_data
                .iter()
                .map(|(index, coeff)| (*coeff, make_index(*index)))
                .collect::<Vec<_>>();
            LinearCombination(lc)
        };
        let constraints = self
            .r1cs
            .constraints
            .par_iter()
            .map(|(a, b, c)| (make_lc(a), make_lc(b), make_lc(c)))
            .collect::<Vec<_>>();
        for (a, b, c) in constraints {
            cs.enforce_r1cs_constraint(|| a, || b, || c)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CircomBuilder, CircomConfig};
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn satisfied() {
        let cfg = CircomConfig::<Fr>::new(
            "./test-vectors/mycircuit_js/mycircuit.wasm",
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
