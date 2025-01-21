use alloy::{providers::ProviderBuilder, sol};
use ark_circom::{ethereum, CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

use ruint::aliases::U256;
use Pairing::{G1Point, G2Point};
use Verifier::{Proof, VerifyingKey};

#[tokio::test]
async fn solidity_verifier() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;
    let inputs = circom.get_public_inputs().unwrap();

    let proof = Groth16::<Bn254>::prove(&params, circom, &mut rng)?;

    // launch the network & compile the verifier
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet();

    // deploy the verifier
    let contract = Groth16Verifier::deploy(provider).await?;

    // check the proof
    let inputs: Vec<U256> = inputs.into_iter().map(|i| i.into()).collect();
    let proof: Proof = ethereum::Proof::from(proof).into();
    let vk: VerifyingKey = ethereum::VerifyingKey::from(params.vk).into();
    let verified = contract.verify(inputs, proof, vk).call().await?._0;

    assert!(verified);

    Ok(())
}

// We need to implement the conversion from the Ark-Circom's internal Ethereum types to
// the ones expected by the abigen'd types. Could we maybe provide a convenience
// macro for these, given that there's room for implementation error?
sol!(
    #[sol(rpc)]
    Groth16Verifier,
    "./tests/verifier_artifact.json"
);

impl From<ethereum::G1> for G1Point {
    fn from(src: ethereum::G1) -> Self {
        Self { X: src.x, Y: src.y }
    }
}
impl From<ethereum::G2> for G2Point {
    fn from(src: ethereum::G2) -> Self {
        // We should use the `.as_tuple()` method which handles converting
        // the G2 elements to have the second limb first
        let src = src.as_tuple();
        Self { X: src.0, Y: src.1 }
    }
}
impl From<ethereum::Proof> for Proof {
    fn from(src: ethereum::Proof) -> Self {
        Self {
            A: src.a.into(),
            B: src.b.into(),
            C: src.c.into(),
        }
    }
}
impl From<ethereum::VerifyingKey> for VerifyingKey {
    fn from(src: ethereum::VerifyingKey) -> Self {
        Self {
            alfa1: src.alpha1.into(),
            beta2: src.beta2.into(),
            gamma2: src.gamma2.into(),
            delta2: src.delta2.into(),
            IC: src.ic.into_iter().map(|i| i.into()).collect(),
        }
    }
}
