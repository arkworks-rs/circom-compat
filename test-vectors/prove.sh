echo "compiling"
circom -f complex-circuit.circom --r1cs --wasm

echo "wtns"
snarkjs wtns calculate complex-circuit.wasm input.json witness.wtns

echo "zkey"
snarkjs zkey new complex-circuit.r1cs powersOfTau28_hez_final_17.ptau complex.zkey

echo "proving 1"
time snarkjs groth16 prove complex.zkey witness.wtns proof.json public.json

echo "proving 2"
time docker run rapidsnark complex.zkey witness.wtns proof.json public.json
