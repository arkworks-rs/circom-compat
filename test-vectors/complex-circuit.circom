template ManyConstraints() {
    signal private input a;
    signal output c;

    signal b;
    signal d;

    c <== a;
    for (var i = 0; i < 10000; i++) {
        c <== c * c;
        b <== c * c;
        d <== c * b;
    }
}

component main = ManyConstraints();
