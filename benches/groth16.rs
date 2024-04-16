use ark_crypto_primitives::snark::SNARK;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use wasmer::Store;

use std::{collections::HashMap, fs::File};

fn bench_groth(c: &mut Criterion, num_validators: u32, num_constraints: u32) {
    let i = num_validators;
    let j = num_constraints;
    let path = format!(
        "./test-vectors/complex-circuit/complex-circuit-{}-{}.zkey",
        i, j
    );
    let mut file = File::open(path).unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
        let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
        values.push(3.into());

        inputs
    };
    let mut store = Store::default();
    let mut wtns = WitnessCalculator::new(
        &mut store,
        format!(
            "./test-vectors/complex-circuit/complex-circuit-{}-{}.wasm",
            i, j
        ),
    )
    .unwrap();
    let full_assignment = wtns
        .calculate_witness_element::<Bn254, _>(&mut store, inputs, false)
        .unwrap();

    let mut rng = thread_rng();
    use ark_std::UniformRand;
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    let inputs = &full_assignment[1..num_inputs];
    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, inputs, &proof).unwrap();

    assert!(verified);

    c.bench_function(&format!("groth proof {} {}", i, j), |b| {
        b.iter(|| {
            black_box(
                Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
                    &params,
                    r,
                    s,
                    &matrices,
                    num_inputs,
                    num_constraints,
                    full_assignment.as_slice(),
                )
                .unwrap(),
            );
        })
    });
}

cfg_if::cfg_if! {
    if #[cfg(feature = "bench-complex-all")] {
        const MIN_NUM_VARIABLES_POWER: u32 = 3;
        const MAX_NUM_VARIABLES_POWER: u32 = 5;
        const MAX_NUM_CONSTRAINTS_POWER: u32 = 5;
        fn groth_all(c: &mut Criterion) {
            for i in MIN_NUM_VARIABLES_POWER..=MAX_NUM_VARIABLES_POWER {
                for j in i..=MAX_NUM_CONSTRAINTS_POWER {
                    let i = 10_u32.pow(i);
                    let j = 10_u32.pow(j);
                    bench_groth(c, i, j);
                }
            }
        }
        criterion_group!(benches, groth_all);
    } else {
      fn groth(c: &mut Criterion) {
        bench_groth(c, 10000, 10000);
      }
      criterion_group!(benches, groth);
    }
}

criterion_main!(benches);
