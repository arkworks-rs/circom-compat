use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use color_eyre::Result;

type GrothBn = Groth16<Bn254>;

#[test]
fn groth16_proof() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", ark_circom::circom::Inputs::BigInt(3.into()));
    builder.push_input("b", ark_circom::circom::Inputs::BigInt(11.into()));

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

#[test]
fn groth16_proof_wrong_input() {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", ark_circom::circom::Inputs::BigInt(3.into()));
    // This isn't a public input to the circuit, should fail
    builder.push_input("foo", ark_circom::circom::Inputs::BigInt(11.into()));

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let _params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let _ = builder.build().unwrap_err();
}

#[test]
#[cfg(feature = "circom-2")]
fn groth16_proof_circom2() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", ark_circom::circom::Inputs::BigInt(3.into()));
    builder.push_input("b", ark_circom::circom::Inputs::BigInt(11.into()));

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

#[test]
#[cfg(feature = "circom-2")]
fn witness_generation_circom2() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", ark_circom::circom::Inputs::BigInt(3.into()));
    builder.push_input(
        "b",
        ark_circom::circom::Inputs::BigInt((0x100000000u64 - 1).into()),
    );

    assert!(builder.build().is_ok());

    Ok(())
}
