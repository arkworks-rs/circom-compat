# run from within test-vectors dir
DIR="test-vectors"
if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist. Please ensure you are running this script from the correct location."
    exit 1
fi

cd "$DIR"

echo "compiling"
circom circuit2.circom --wasm --r1cs

node circuit2_js/generate_witness.js circuit2_js/circuit2.wasm mycircuit-input1.json circuit2_js/witness.wtns

snarkjs wej circuit2_js/witness.wtns safe-circuit-witness.json