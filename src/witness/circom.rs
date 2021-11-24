use color_eyre::Result;
use wasmer::{Function, Instance, Value};

#[derive(Clone, Debug)]
pub struct Wasm(Instance);

impl Wasm {
    pub fn new(instance: Instance) -> Self {
        Self(instance)
    }

    pub fn init(&self, sanity_check: bool) -> Result<()> {
        let func = self.func("init");
        func.call(&[Value::I32(sanity_check as i32)])?;
        Ok(())
    }


    // Circom 2.0
    pub fn get_version(&self) -> Result<i32> {
        self.get_i32("getVersion")
    }

    // Circom 1
    pub fn get_fr_len(&self) -> Result<i32> {
        self.get_i32("getFrLen")
    }

    // Circom 2.0
    pub fn get_field_num_len32(&self) -> Result<i32> {
        self.get_i32("getFieldNumLen32")
    }

    // Circom 1
    pub fn get_ptr_raw_prime(&self) -> Result<i32> {
        self.get_i32("getPRawPrime")
    }

    // Circom 2.0
    pub fn get_raw_prime(&self) -> Result<()> {
        let func = self.func("getRawPrime");
        let _result = func.call(&[])?;
        Ok(())
    }

    pub fn get_n_vars(&self) -> Result<i32> {
        self.get_i32("getNVars")
    }

    pub fn get_ptr_witness_buffer(&self) -> Result<i32> {
        self.get_i32("getWitnessBuffer")
    }

    pub fn get_ptr_witness(&self, w: i32) -> Result<i32> {
        let func = self.func("getPWitness");
        let res = func.call(&[w.into()])?;

        Ok(res[0].unwrap_i32())
    }

    pub fn get_signal_offset32(
        &self,
        p_sig_offset: u32,
        component: u32,
        hash_msb: u32,
        hash_lsb: u32,
    ) -> Result<()> {
        let func = self.func("getSignalOffset32");
        func.call(&[
            p_sig_offset.into(),
            component.into(),
            hash_msb.into(),
            hash_lsb.into(),
        ])?;

        Ok(())
    }

    pub fn set_signal(&self, c_idx: i32, component: i32, signal: i32, p_val: i32) -> Result<()> {
        let func = self.func("setSignal");
        func.call(&[c_idx.into(), component.into(), signal.into(), p_val.into()])?;

        Ok(())
    }

    fn get_i32(&self, name: &str) -> Result<i32> {
        let func = self.func(name);
        let result = func.call(&[])?;
        Ok(result[0].unwrap_i32())
    }

    fn func(&self, name: &str) -> &Function {
        self.0
            .exports
            .get_function(name)
            .unwrap_or_else(|_| panic!("function {} not found", name))
    }
}
