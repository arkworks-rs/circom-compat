use super::{fnv, SafeMemory, Wasm};
use ark_ff::PrimeField;
use color_eyre::Result;
use num_bigint::BigInt;
use num_traits::Zero;
use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, RuntimeError, Store};
use wasmer_wasix::WasiEnv;

use num::ToPrimitive;

#[derive(Debug)]
pub struct WitnessCalculator {
    pub instance: Wasm,
    pub memory: Option<SafeMemory>,
    pub n64: u32,
    pub prime: BigInt,
}

// Error type to signal end of execution.
// From https://docs.wasmer.io/integrations/examples/exit-early
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("{0}")]
struct ExitCode(u32);

fn from_array32(arr: Vec<u32>) -> BigInt {
    let mut res = BigInt::zero();
    let radix = BigInt::from(0x100000000u64);
    for &val in arr.iter() {
        res = res * &radix + BigInt::from(val);
    }
    res
}

fn to_array32(s: &BigInt, size: usize) -> Vec<u32> {
    let mut res = vec![0; size];
    let mut rem = s.clone();
    let radix = BigInt::from(0x100000000u64);
    let mut c = size;
    while !rem.is_zero() {
        c -= 1;
        res[c] = (&rem % &radix).to_u32().unwrap();
        rem /= &radix;
    }

    res
}

impl WitnessCalculator {
    pub fn new(store: &mut Store, path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_file(store, path)
    }

    pub fn from_file(store: &mut Store, path: impl AsRef<std::path::Path>) -> Result<Self> {
        let module = Module::from_file(&store, path)?;
        Self::from_module(store, module)
    }

    pub fn from_module(store: &mut Store, module: Module) -> Result<Self> {
        let wasm = Self::make_wasm_runtime(store, module)?;
        Self::new_from_wasm(store, wasm)
    }

    pub fn make_wasm_runtime(store: &mut Store, module: Module) -> Result<Wasm> {
        let memory = Memory::new(store, MemoryType::new(2000, None, false)).unwrap();
        let import_object = imports! {
            "env" => {
                "memory" => memory.clone(),
            },
            // Host function callbacks from the WASM
            "runtime" => {
                "error" => runtime::error(store),
                "logSetSignal" => runtime::log_signal(store),
                "logGetSignal" => runtime::log_signal(store),
                "logFinishComponent" => runtime::log_component(store),
                "logStartComponent" => runtime::log_component(store),
                "log" => runtime::log_component(store),
                "exceptionHandler" => runtime::exception_handler(store),
                "showSharedRWMemory" => runtime::show_memory(store),
                "printErrorMessage" => runtime::print_error_message(store),
                "writeBufferMessage" => runtime::write_buffer_message(store),
            }
        };
        let instance = Instance::new(store, &module, &import_object)?;
        let exports = instance.exports.clone();
        let mut wasi_env = WasiEnv::builder("calculateWitness").finalize(store)?;
        wasi_env.initialize_with_memory(store, instance, Some(memory.clone()), false)?;
        let wasm = Wasm::new(exports, memory);
        Ok(wasm)
    }

    pub fn new_from_wasm(store: &mut Store, instance: Wasm) -> Result<Self> {
        let n32 = instance.get_field_num_len32(store)?;
        instance.get_raw_prime(store)?;
        let mut arr = vec![0; n32 as usize];
        for i in 0..n32 {
            let res = instance.read_shared_rw_memory(store, i)?;
            arr[(n32 as usize) - (i as usize) - 1] = res;
        }
        let prime = from_array32(arr);

        let n64 = ((prime.bits() - 1) / 64 + 1) as u32;

        Ok(WitnessCalculator {
            instance,
            memory: None,
            n64,
            prime,
        })
    }

    pub fn calculate_witness<I: IntoIterator<Item = (String, Vec<BigInt>)>>(
        &mut self,
        store: &mut Store,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<BigInt>> {
        self.instance.init(store, sanity_check)?;

        let n32 = self.instance.get_field_num_len32(store)?;

        // allocate the inputs
        for (name, values) in inputs.into_iter() {
            let (msb, lsb) = fnv(&name);

            for (i, value) in values.into_iter().enumerate() {
                let f_arr = to_array32(&value, n32 as usize);
                for j in 0..n32 {
                    self.instance.write_shared_rw_memory(
                        store,
                        j,
                        f_arr[(n32 as usize) - 1 - (j as usize)],
                    )?;
                }
                self.instance.set_input_signal(store, msb, lsb, i as u32)?;
            }
        }

        let mut w = Vec::new();

        let witness_size = self.instance.get_witness_size(store)?;
        for i in 0..witness_size {
            self.instance.get_witness(store, i)?;
            let mut arr = vec![0; n32 as usize];
            for j in 0..n32 {
                arr[(n32 as usize) - 1 - (j as usize)] =
                    self.instance.read_shared_rw_memory(store, j)?;
            }
            w.push(from_array32(arr));
        }

        Ok(w)
    }

    pub fn calculate_witness_element<
        F: PrimeField,
        I: IntoIterator<Item = (String, Vec<BigInt>)>,
    >(
        &mut self,
        store: &mut Store,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<F>> {
        let modulus = F::MODULUS;
        let witness = self.calculate_witness(store, inputs, sanity_check)?;

        // convert it to field elements
        use num_traits::Signed;
        let witness = witness
            .into_iter()
            .map(|w| {
                let w = if w.sign() == num_bigint::Sign::Minus {
                    // Need to negate the witness element if negative
                    modulus.into() - w.abs().to_biguint().unwrap()
                } else {
                    w.to_biguint().unwrap()
                };
                F::from(w)
            })
            .collect::<Vec<_>>();

        Ok(witness)
    }
}

// callback hooks for debugging
mod runtime {
    use super::*;

    pub fn error(store: &mut Store) -> Function {
        #[allow(unused)]
        #[allow(clippy::many_single_char_names)]
        fn func(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> Result<(), RuntimeError> {
            // NOTE: We can also get more information why it is failing, see p2str etc here:
            // https://github.com/iden3/circom_runtime/blob/master/js/witness_calculator.js#L52-L64
            println!("runtime error, exiting early: {a} {b} {c} {d} {e} {f}",);
            Err(RuntimeError::user(Box::new(ExitCode(1))))
        }
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn exception_handler(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn show_memory(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn print_error_message(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    // Circom 2.0
    pub fn write_buffer_message(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_typed(store, func)
    }

    pub fn log_signal(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func(a: i32, b: i32) {}
        Function::new_typed(store, func)
    }

    pub fn log_component(store: &mut Store) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_typed(store, func)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, path::PathBuf};

    struct TestCase<'a> {
        circuit_path: &'a str,
        inputs_path: &'a str,
        n64: u32,
        witness: &'a [&'a str],
    }

    pub fn root_path(p: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(p);
        path.to_string_lossy().to_string()
    }

    #[tokio::test]
    async fn multiplier_1() {
        run_test(TestCase {
            circuit_path: root_path("test-vectors/mycircuit_js/mycircuit.wasm").as_str(),
            inputs_path: root_path("test-vectors/mycircuit-input1.json").as_str(),
            n64: 4,
            witness: &["1", "33", "3", "11"],
        });
    }

    #[tokio::test]
    async fn multiplier_2() {
        run_test(TestCase {
            circuit_path: root_path("test-vectors/mycircuit_js/mycircuit.wasm").as_str(),
            inputs_path: root_path("test-vectors/mycircuit-input2.json").as_str(),
            n64: 4,
            witness: &[
                "1",
                "21888242871839275222246405745257275088548364400416034343698204186575672693159",
                "21888242871839275222246405745257275088548364400416034343698204186575796149939",
                "11",
            ],
        });
    }

    #[tokio::test]
    async fn multiplier_3() {
        run_test(TestCase {
            circuit_path: root_path("test-vectors/mycircuit_js/mycircuit.wasm").as_str(),
            inputs_path: root_path("test-vectors/mycircuit-input3.json").as_str(),
            n64: 4,
            witness: &[
                "1",
                "21888242871839275222246405745257275088548364400416034343698204186575808493616",
                "10944121435919637611123202872628637544274182200208017171849102093287904246808",
                "2",
            ],
        });
    }

    #[tokio::test]
    async fn safe_multipler() {
        let witness =
            std::fs::read_to_string(root_path("test-vectors/safe-circuit-witness.json")).unwrap();
        let witness: Vec<String> = serde_json::from_str(&witness).unwrap();
        let witness = &witness.iter().map(|x| x.as_ref()).collect::<Vec<_>>();
        run_test(TestCase {
            circuit_path: root_path("test-vectors/circuit2_js/circuit2.wasm").as_str(),
            inputs_path: root_path("test-vectors/mycircuit-input1.json").as_str(),
            n64: 4,
            witness,
        });
    }

    use serde_json::Value;
    use std::str::FromStr;

    fn value_to_bigint(v: Value) -> BigInt {
        match v {
            Value::String(inner) => BigInt::from_str(&inner).unwrap(),
            Value::Number(inner) => BigInt::from(inner.as_u64().expect("not a u32")),
            _ => panic!("unsupported type"),
        }
    }

    fn run_test(case: TestCase) {
        let mut store = Store::default();
        let mut wtns = WitnessCalculator::new(&mut store, case.circuit_path).unwrap();
        assert_eq!(
            wtns.prime.to_str_radix(16),
            "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001".to_lowercase()
        );
        assert_eq!({ wtns.n64 }, case.n64);

        let inputs_str = std::fs::read_to_string(case.inputs_path).unwrap();
        let inputs: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_str(&inputs_str).unwrap();

        let inputs = inputs
            .iter()
            .map(|(key, value)| {
                let res = match value {
                    Value::String(inner) => {
                        vec![BigInt::from_str(inner).unwrap()]
                    }
                    Value::Number(inner) => {
                        vec![BigInt::from(inner.as_u64().expect("not a u32"))]
                    }
                    Value::Array(inner) => inner.iter().cloned().map(value_to_bigint).collect(),
                    _ => panic!(),
                };

                (key.clone(), res)
            })
            .collect::<HashMap<_, _>>();

        let res = wtns.calculate_witness(&mut store, inputs, false).unwrap();
        for (r, w) in res.iter().zip(case.witness) {
            assert_eq!(r, &BigInt::from_str(w).unwrap());
        }
    }
}
