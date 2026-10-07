use std::{
    error::Error,
    fs,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use wasmi::{Engine, Instance, Linker, Memory, Module, Store};

const SIGNER_SHA256: &str = "96b78cd607c279183264e14501b649bc44f3a5372433bc2df482d648ba9d1001";
const TEST_FINGERPRINT: &str = "73c5da0a";

struct SignerHost {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
}

impl SignerHost {
    fn new(wasm: &[u8]) -> Result<(Self, Duration), Box<dyn Error>> {
        let digest = Sha256::digest(wasm)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if digest != SIGNER_SHA256 {
            return Err(format!("unexpected signer.wasm hash: {digest}").into());
        }

        let engine = Engine::default();
        let started = Instant::now();
        let module = Module::new(&engine, wasm)?;
        if module.imports().next().is_some() {
            return Err("signer.wasm must not have imports".into());
        }
        let mut store = Store::new(&engine, ());
        let linker = Linker::<()>::new(&engine);
        let instance = linker.instantiate_and_start(&mut store, &module)?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or("signer.wasm has no exported memory")?;
        Ok((
            Self {
                store,
                instance,
                memory,
            },
            started.elapsed(),
        ))
    }

    fn call0(&mut self, name: &str) -> Result<i32, Box<dyn Error>> {
        let function = self.instance.get_typed_func::<(), i32>(&self.store, name)?;
        Ok(function.call(&mut self.store, ())?)
    }

    fn call_i32_i32(&mut self, name: &str, a: i32, b: i32) -> Result<i32, Box<dyn Error>> {
        let function = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&self.store, name)?;
        Ok(function.call(&mut self.store, (a, b))?)
    }

    fn call_void(&mut self, name: &str) -> Result<(), Box<dyn Error>> {
        let function = self.instance.get_typed_func::<(), ()>(&self.store, name)?;
        function.call(&mut self.store, ())?;
        Ok(())
    }

    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let function = self
            .instance
            .get_typed_func::<i32, i32>(&self.store, "signer_init")?;
        if function.call(&mut self.store, 0)? != 1 {
            return Err("signer_init failed".into());
        }
        Ok(())
    }

    fn seed_from_mnemonic(&mut self, mnemonic: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let mut input = None;
        let result = (|| -> Result<(), Box<dyn Error>> {
            let capacity = self.call0("signer_input_cap")? as u32 as usize;
            if mnemonic.len() > capacity {
                return Err("mnemonic exceeds signer input capacity".into());
            }
            let offset = self.call0("signer_input")? as u32 as usize;
            input = Some(offset);
            self.memory.write(&mut self.store, offset, mnemonic)?;
            if self.call_i32_i32("signer_seed_from_mnemonic", mnemonic.len() as i32, 0)? != 1 {
                return Err("signer_seed_from_mnemonic failed".into());
            }
            Ok(())
        })();

        if let Some(offset) = input {
            let zeroes = vec![0; mnemonic.len()];
            let _ = self.memory.write(&mut self.store, offset, &zeroes);
        }
        mnemonic.fill(0);
        result
    }

    fn fingerprint(&mut self) -> Result<String, Box<dyn Error>> {
        Ok(format!("{:08x}", self.call0("signer_fingerprint")? as u32))
    }

    fn unload(&mut self) -> Result<(), Box<dyn Error>> {
        self.call_void("signer_unload")
    }
}

impl Drop for SignerHost {
    fn drop(&mut self) {
        let _ = self.call_void("signer_unload");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../../../build/signer.wasm".into());
    let wasm = fs::read(path)?;

    let (mut signer, module_load) = SignerHost::new(&wasm)?;
    let init_started = Instant::now();
    signer.init()?;
    let init_time = init_started.elapsed();

    let mut mnemonic = ("abandon ".repeat(11) + "about").into_bytes();
    let seed_started = Instant::now();
    signer.seed_from_mnemonic(&mut mnemonic)?;
    let seed_time = seed_started.elapsed();
    let fingerprint = signer.fingerprint()?;
    if fingerprint != TEST_FINGERPRINT {
        return Err(format!("unexpected test fingerprint: {fingerprint}").into());
    }
    signer.unload()?;

    println!("target={}-{}", std::env::consts::ARCH, std::env::consts::OS);
    println!("wasmi=2.0.0 imports=0 fingerprint_check=ok");
    println!("module_load_ms={:.2}", module_load.as_secs_f64() * 1000.0);
    println!("signer_init_ms={:.2}", init_time.as_secs_f64() * 1000.0);
    println!("seed_derivation_ms={:.2}", seed_time.as_secs_f64() * 1000.0);
    Ok(())
}
