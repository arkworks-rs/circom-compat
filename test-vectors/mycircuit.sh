# run from within test-vectors dir
DIR="test-vectors"
if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist. Please ensure you are running this script from the correct location."
    exit 1
fi

cd "$DIR"

echo "compiling"
circom mycircuit.circom --r1cs --wasm

FILE="powersOfTau28_hez_final_17.ptau"
if [ ! -f "$FILE" ]; then
    echo "getting powers of tau"
    curl -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau
else
    echo "$FILE already exists"
fi


echo "writing zkey"
snarkjs zkey new mycircuit.r1cs powersOfTau28_hez_final_17.ptau test.zkey
