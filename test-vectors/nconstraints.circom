template A(n) {
  signal input in;
  signal output out;

  signal intermediate[n];

  intermediate[0] <== in;
  for (var i=1; i<n; i++) {
    intermediate[i] <== intermediate[i-1] * intermediate[i-1] + i;
  }
  out <== intermediate[n-1];
}

component main = A({{N}});
