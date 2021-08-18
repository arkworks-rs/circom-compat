template ManyConstraints() {
    signal private input a;
    signal output c;

    signal b[10000];
    signal d[10000];

    b[0] <== a;
    d[0] <== a*a;
    for (var i = 1; i < 10000; i++) {
        b[i] <== b[i-1]*b[i-1];
        d[i] <== d[i-1]*b[i-1];
    }
    c <== d[9999];
}

component main = ManyConstraints();
