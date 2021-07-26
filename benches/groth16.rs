use criterion::{criterion_group, criterion_main, Criterion};

use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};


fn groth(c: &mut Criterion) {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/complex-circuit.wasm",
        "./test-vectors/complex-circuit.r1cs",
    ).unwrap();

    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

    let circom = builder.build().unwrap();

    let inputs = circom.get_public_inputs().unwrap();

    let proof = prove(circom.clone(), &params, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);
    let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
    assert!(verified);

    c.bench_function("groth proof", |b| b.iter(|| {
        prove(circom.clone(), &params, &mut rng).unwrap()
    }));
}

criterion_group!(benches, groth);
criterion_main!(benches);
