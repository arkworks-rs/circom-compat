use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

type GrothBn = Groth16<Bn254>;

#[tokio::test]
async fn groth16_proof() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "./test-vectors/mycircuit_js/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);

    Ok(())
}

#[tokio::test]
async fn groth16_proof_wrong_input() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "./test-vectors/mycircuit_js/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    // This isn't a public input to the circuit, should fail verification
    builder.push_input("foo", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let circom = builder.build().unwrap();

    // we need to manually specify the public input, else the circuit builder will take the default for b = 0, and set public input to 0 (=11*0).
    let inputs = vec![Fr::from(33u64)];

    let proof = GrothBn::prove(&params, circom, &mut rng).unwrap();

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    assert!(!verified);

    Ok(())
}

#[tokio::test]
async fn groth16_proof_circom() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "test-vectors/circuit2_js/circuit2.wasm",
        "test-vectors/circuit2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);

    Ok(())
}

#[tokio::test]
async fn witness_generation_circom() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "test-vectors/circuit2_js/circuit2.wasm",
        "test-vectors/circuit2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 0x100000000u64 - 1);

    assert!(builder.build().is_ok());

    Ok(())
}
