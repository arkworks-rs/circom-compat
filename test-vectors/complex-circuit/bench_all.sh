MIN_NUM_VARIABLES=$1
MAX_NUM_VARIABLES=$2
MAX_NUM_CONSTRAINTS=$3

for i in `seq 10 19`; do wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_$i.ptau; done

./prepare.sh $MIN_NUM_VARIABLES $MAX_NUM_VARIABLES $MAX_NUM_CONSTRAINTS

for i in `seq $MIN_NUM_VARIABLES $MAX_NUM_VARIABLES`
do
  for j in `seq $i $MAX_NUM_CONSTRAINTS`
  do
    NUM_VARIABLES=$(echo 10^$i | bc)
    NUM_CONSTRAINTS=$(echo 10^$j | bc)
    echo "**** START benchmarking $NUM_VARIABLES $NUM_CONSTRAINTS ****"
    ./prove.sh $NUM_VARIABLES $NUM_CONSTRAINTS
    perf stat -r5 rapidsnark complex-circuit-$NUM_VARIABLES-$NUM_CONSTRAINTS.zkey witness.wtns proof.json public.json
    echo "**** END benchmarking $NUM_VARIABLES $NUM_CONSTRAINTS ****"
  done
done
