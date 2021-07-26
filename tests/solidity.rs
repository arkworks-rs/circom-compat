use ark_circom::{
    ethereum::{Inputs, Proof, VerifyingKey},
    CircomBuilder, CircomConfig,
};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_groth16::{create_random_proof as prove, generate_random_parameters};

use ethers::{
    contract::{abigen, ContractError, ContractFactory},
    providers::{Http, Middleware, Provider},
    utils::{compile_and_launch_ganache, Ganache, Solc},
};

use std::{convert::TryFrom, sync::Arc};

#[tokio::test]
async fn solidity_verifier() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;
    let inputs = circom.get_public_inputs().unwrap();

    let proof = prove(circom, &params, &mut rng)?;

    // launch the network & compile the verifier
    let (compiled, ganache) =
        compile_and_launch_ganache(Solc::new("./tests/verifier.sol"), Ganache::new()).await?;
    let acc = ganache.addresses()[0];
    let provider = Provider::<Http>::try_from(ganache.endpoint())?;
    let provider = provider.with_sender(acc);
    let provider = Arc::new(provider);

    // deploy the verifier
    let contract = {
        let contract = compiled
            .get("TestVerifier")
            .expect("could not find contract");

        let factory = ContractFactory::new(
            contract.abi.clone(),
            contract.bytecode.clone(),
            provider.clone(),
        );
        let contract = factory.deploy(())?.send().await?;
        let addr = contract.address();
        Groth16Verifier::new(addr, provider)
    };

    // check the proof
    let verified = contract
        .check_proof(proof, params.vk, inputs.as_slice())
        .await?;
    assert!(verified);

    Ok(())
}

abigen!(Groth16Verifier, "./tests/verifier_abi.json");

impl<M: Middleware> Groth16Verifier<M> {
    async fn check_proof<I: Into<Inputs>, P: Into<Proof>, VK: Into<VerifyingKey>>(
        &self,
        proof: P,
        vk: VK,
        inputs: I,
    ) -> Result<bool, ContractError<M>> {
        // convert into the expected format by the contract
        let proof = proof.into().as_tuple();
        let vk = vk.into().as_tuple();
        let inputs = inputs.into().0;

        // query the contract
        let res = self.verify(inputs, proof, vk).call().await?;

        Ok(res)
    }
}
