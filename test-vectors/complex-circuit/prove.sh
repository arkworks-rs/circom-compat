NUM_VARIABLES=$1
NUM_CONSTRAINTS=$2

snarkjs wtns calculate complex-circuit-$NUM_VARIABLES-$NUM_CONSTRAINTS.wasm input.json witness.wtns
snarkjs groth16 prove complex-circuit-$NUM_VARIABLES-$NUM_CONSTRAINTS.zkey witness.wtns proof.json public.json
snarkjs zkey export verificationkey complex-circuit-$NUM_VARIABLES-$NUM_CONSTRAINTS.zkey
snarkjs groth16 verify verification_key.json proof.json public.json

