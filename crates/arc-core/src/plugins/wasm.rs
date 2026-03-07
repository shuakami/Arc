use crate::config::WasmPluginConfig;
use ahash::AHashMap;
use std::sync::Arc;
use wasmtime::{Config, Engine, Module};

#[derive(Clone)]
pub struct WasmPlugin {
    pub name: Arc<str>,
    pub module: Arc<Module>,
    pub budget_us: u64,
}

#[derive(Clone)]
pub struct WasmRegistry {
    pub engine: Arc<Engine>,
    pub plugins: Arc<AHashMap<Arc<str>, WasmPlugin>>,
}

impl WasmRegistry {
    pub fn build(cfgs: &[WasmPluginConfig]) -> anyhow::Result<Self> {
        let mut c = Config::new();
        c.consume_fuel(true);
        c.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = Engine::new(&c)?;

        let mut plugins = AHashMap::new();
        for p in cfgs {
            let bytes = std::fs::read(&p.file)?;
            let module = Module::from_binary(&engine, &bytes)?;
            plugins.insert(
                Arc::<str>::from(p.name.clone()),
                WasmPlugin {
                    name: Arc::<str>::from(p.name.clone()),
                    module: Arc::new(module),
                    budget_us: p.budget.as_micros() as u64,
                },
            );
        }

        Ok(Self {
            engine: Arc::new(engine),
            plugins: Arc::new(plugins),
        })
    }
}
