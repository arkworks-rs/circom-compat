template CheckBits(n) {
    signal input in;
    signal bits[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] -1 ) === 0;
        lc1 += bits[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

template Multiplier(n) {
    signal private input a;
    signal private input b;
    signal output c;
    signal inva;
    signal invb;

    component chackA = CheckBits(n);
    component chackB = CheckBits(n);

    chackA.in <== a;
    chackB.in <== b;

    inva <-- 1/(a-1);
    (a-1)*inva === 1;

    invb <-- 1/(b-1);
    (b-1)*invb === 1;

    c <== a*b;
}

component main = Multiplier(64);
