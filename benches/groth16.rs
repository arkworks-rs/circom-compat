use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{create_proof_with_qap_and_matrices, prepare_verifying_key, verify_proof};

use std::{collections::HashMap, fs::File};

fn groth(c: &mut Criterion) {
    let path = "./test-vectors/complex.zkey";
    let mut file = File::open(path).unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
        let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
        values.push(3.into());

        let values = inputs.entry("b".to_string()).or_insert_with(Vec::new);
        values.push(11.into());

        inputs
    };

    let mut wtns = WitnessCalculator::new("./test-vectors/complex-circuit.wasm").unwrap();
    let full_assignment = wtns
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .unwrap();

    let mut rng = thread_rng();
    use ark_std::UniformRand;
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let proof = create_proof_with_qap_and_matrices::<_, CircomReduction>(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &full_assignment[1..num_inputs];
    let verified = verify_proof(&pvk, &proof, inputs).unwrap();

    assert!(verified);

    c.bench_function("groth proof", |b| {
        b.iter(|| {
            black_box(
                create_proof_with_qap_and_matrices::<_, CircomReduction>(
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

criterion_group!(benches, groth);
criterion_main!(benches);
