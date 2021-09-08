for i in `seq 3 5`
do
  for j in `seq $i 5`
  do
    NUM_VARIABLES=$(echo 10^$i | bc)
    NUM_CONSTRAINTS=$(echo 10^$j | bc)
    sed "s/NUM_VARIABLES_TEMPLATE/$NUM_VARIABLES/g;s/NUM_CONSTRAINTS_TEMPLATE/$NUM_CONSTRAINTS/g" complex-circuit.circom.template > complex-circuit-$NUM_VARIABLES-$NUM_CONSTRAINTS.circom
    ./build.sh $NUM_VARIABLES $NUM_CONSTRAINTS
  done
done
