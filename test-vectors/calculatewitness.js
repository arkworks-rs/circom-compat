#!/usr/bin/env node

const fs = require("fs");
const {stringifyBigInts, unstringifyBigInts} = require("snarkjs");
const WitnessCalculatorBuilder = require("./witness_calculator.js");

// const wasmName = "smtverifier10.wasm"
// const inputName = "smtverifier10-input.json"

const wasmName = "nconstraints.wasm"
const inputName = "nconstraints-input.json"

async function run () {
  const wasm = await fs.promises.readFile(wasmName);
  const input = unstringifyBigInts(JSON.parse(await fs.promises.readFile(inputName, "utf8")));

  console.log("input:", input);
  let options;
  const wc = await WitnessCalculatorBuilder(wasm, options);

  const w = await wc.calculateWitness(input);

  console.log("witness:\n", JSON.stringify(stringifyBigInts(w)));

  // const wb = await wc.calculateBinWitness(input);

  // console.log("witnessBin:", Buffer.from(wb).toString('hex'));

  // await fs.promises.writeFile(witnessName, JSON.stringify(stringifyBigInts(w), null, 1));

}

run().then(() => {
    process.exit();
});
