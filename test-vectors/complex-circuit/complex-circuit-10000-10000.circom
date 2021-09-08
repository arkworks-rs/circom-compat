template ManyConstraints(NUM_VARIABLES, NUM_CONSTRAINTS) {
    signal private input a;
    signal output c;

    assert(NUM_VARIABLES <= NUM_CONSTRAINTS)

    signal b[NUM_VARIABLES];

    b[0] <== a*a;
    var i;
    for (i = 1; i < NUM_VARIABLES; i++) {
        b[i] <== b[i-1]*b[i-1];
    }
    i = i-1;
    for (var j = NUM_VARIABLES; j < NUM_CONSTRAINTS; j++) {
        b[i] === b[i-1]*b[i-1];
    }
    c <== b[i];
}

component main = ManyConstraints(10000, 10000);
