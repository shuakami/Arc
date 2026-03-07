use arc_common::{ArcError, Result};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use wasmtime::{Caller, Engine, Extern, Linker, Memory, Module, Store, TypedFunc};

#[derive(Debug, Clone)]
pub struct PluginDef {
    pub name: Arc<str>,
    pub module: Arc<Module>,
    pub pool: usize,
    pub timeout_ms: u64,
}

#[derive(Clone)]
pub struct PluginCatalog {
    engine: Arc<Engine>,
    defs: Arc<[PluginDef]>,
}

impl core::fmt::Debug for PluginCatalog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginCatalog")
            .field("defs", &self.defs)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RequestView<'a> {
    pub method: &'a [u8],
    pub path: &'a [u8],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PluginVerdict {
    pub allowed: bool,
    pub deny_status: u16,
}

impl PluginVerdict {
    #[inline]
    pub fn allow() -> Self {
        Self {
            allowed: true,
            deny_status: 0,
        }
    }

    #[inline]
    pub fn deny(status: u16) -> Self {
        Self {
            allowed: false,
            deny_status: status,
        }
    }
}

#[derive(Debug)]
struct HostState {
    deny_status: u16,
}

pub struct WorkerPlugins {
    pools: Vec<PluginVmPool>,
}

struct PluginVmPool {
    def: PluginDef,
    vms: Vec<PluginVm>,
}

struct PluginVm {
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    dealloc: TypedFunc<(i32, i32), ()>,
    on_request: Option<TypedFunc<(i32, i32, i32, i32), i32>>,
}

static EPOCH_THREAD: OnceLock<()> = OnceLock::new();

impl PluginCatalog {
    pub fn load_from_defs(defs: Vec<(String, String, usize, u64)>) -> Result<Self> {
        let mut cfg = wasmtime::Config::new();
        // epoch interruption: used for hard timeout isolation
        cfg.epoch_interruption(true);

        let engine =
            Engine::new(&cfg).map_err(|_| ArcError::plugin("failed to create wasmtime engine"))?;
        let engine = Arc::new(engine);

        start_epoch_thread(engine.clone());

        let mut out: Vec<PluginDef> = Vec::with_capacity(defs.len());
        for (name, path, pool, timeout_ms) in defs {
            if pool == 0 {
                return Err(ArcError::config(format!("plugin pool must be > 0: {name}")));
            }
            if timeout_ms == 0 {
                return Err(ArcError::config(format!(
                    "plugin timeout_ms must be > 0: {name}"
                )));
            }
            let module = Module::from_file(&engine, &path)
                .map_err(|_| ArcError::plugin("failed to compile wasm module"))?;
            out.push(PluginDef {
                name: Arc::from(name),
                module: Arc::new(module),
                pool,
                timeout_ms,
            });
        }

        Ok(Self {
            engine,
            defs: out.into(),
        })
    }

    #[inline]
    pub fn defs(&self) -> &[PluginDef] {
        &self.defs
    }

    pub fn build_worker(&self) -> Result<WorkerPlugins> {
        let mut pools: Vec<PluginVmPool> = Vec::with_capacity(self.defs.len());
        for def in self.defs.iter().cloned() {
            let mut vms = Vec::with_capacity(def.pool);
            for _ in 0..def.pool {
                let vm = instantiate_vm(self.engine.clone(), def.clone())?;
                vms.push(vm);
            }
            pools.push(PluginVmPool { def, vms });
        }
        Ok(WorkerPlugins { pools })
    }
}

impl WorkerPlugins {
    #[inline]
    pub fn plugin_count(&self) -> usize {
        self.pools.len()
    }

    #[inline]
    pub fn exec_on_request(&mut self, plugin_id: usize, req: RequestView<'_>) -> PluginVerdict {
        let pool = match self.pools.get_mut(plugin_id) {
            Some(p) => p,
            None => return PluginVerdict::deny(500),
        };

        let mut vm = match pool.vms.pop() {
            Some(vm) => vm,
            None => {
                // pool exhausted: fail-closed
                return PluginVerdict::deny(503);
            }
        };

        let verdict = exec_vm_request(&mut vm, &pool.def, req);

        // 如果 vm 在执行中产生致命错误，可选择丢弃 vm 并重建（非热路径、但这里不重建以避免分配）。
        pool.vms.push(vm);
        verdict
    }
}

fn start_epoch_thread(engine: Arc<Engine>) {
    let _ = EPOCH_THREAD.get_or_init(|| {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(1));
            engine.increment_epoch();
        });
    });
}

fn instantiate_vm(engine: Arc<Engine>, def: PluginDef) -> Result<PluginVm> {
    let mut linker: Linker<HostState> = Linker::new(&engine);

    linker
        .func_wrap(
            "arc",
            "arc_deny",
            |mut caller: Caller<'_, HostState>, status: i32| {
                let s = if status < 100 || status > 599 {
                    500
                } else {
                    status
                };
                caller.data_mut().deny_status = s as u16;
            },
        )
        .map_err(|_| ArcError::plugin("failed to define host import arc_deny"))?;

    let mut store = Store::new(&engine, HostState { deny_status: 0 });

    // 默认 deadline：一个很大的值；每次调用前再设置为 timeout。
    store.set_epoch_deadline(u64::MAX / 2);

    let instance = linker
        .instantiate(&mut store, def.module.as_ref())
        .map_err(|_| ArcError::plugin("failed to instantiate wasm module"))?;

    let memory = match instance.get_export(&mut store, "memory") {
        Some(Extern::Memory(m)) => m,
        _ => return Err(ArcError::plugin("plugin missing export memory")),
    };

    let alloc = instance
        .get_typed_func::<i32, i32>(&mut store, "alloc")
        .map_err(|_| ArcError::plugin("plugin missing export alloc(i32)->i32"))?;

    let dealloc = instance
        .get_typed_func::<(i32, i32), ()>(&mut store, "dealloc")
        .map_err(|_| ArcError::plugin("plugin missing export dealloc(i32,i32)"))?;

    let on_request = instance
        .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "on_request")
        .ok();

    Ok(PluginVm {
        store,
        memory,
        alloc,
        dealloc,
        on_request,
    })
}

fn exec_vm_request(vm: &mut PluginVm, def: &PluginDef, req: RequestView<'_>) -> PluginVerdict {
    vm.store.data_mut().deny_status = 0;

    // epoch deadline: 以 1ms epoch tick 为基准，timeout_ms 直接映射为 deadline。
    vm.store.set_epoch_deadline(def.timeout_ms.max(1));

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(f) = vm.on_request.as_ref() else {
            return Ok::<i32, ()>(0);
        };

        // alloc + write method
        let mlen = req.method.len().min(i32::MAX as usize) as i32;
        let mptr = vm.alloc.call(&mut vm.store, mlen).map_err(|_| ())?;
        if write_wasm_mem(&mut vm.store, vm.memory, mptr, req.method).is_err() {
            return Err(());
        }

        // alloc + write path
        let plen = req.path.len().min(i32::MAX as usize) as i32;
        let pptr = vm.alloc.call(&mut vm.store, plen).map_err(|_| ())?;
        if write_wasm_mem(&mut vm.store, vm.memory, pptr, req.path).is_err() {
            // best-effort free
            let _ = vm.dealloc.call(&mut vm.store, (mptr, mlen));
            return Err(());
        }

        let rc = f
            .call(&mut vm.store, (mptr, mlen, pptr, plen))
            .map_err(|_| ())?;

        // best-effort free
        let _ = vm.dealloc.call(&mut vm.store, (mptr, mlen));
        let _ = vm.dealloc.call(&mut vm.store, (pptr, plen));

        Ok(rc)
    }));

    // reset deadline to large
    vm.store.set_epoch_deadline(u64::MAX / 2);

    let mut deny = vm.store.data().deny_status;

    let rc = match res {
        Ok(Ok(v)) => v,
        _ => {
            // panic 或 wasmtime 调用失败：隔离为 500
            deny = 500;
            500
        }
    };

    if deny != 0 {
        return PluginVerdict::deny(deny);
    }

    if rc == 0 {
        return PluginVerdict::allow();
    }

    if (100..=599).contains(&rc) {
        return PluginVerdict::deny(rc as u16);
    }

    PluginVerdict::deny(500)
}

fn write_wasm_mem(store: &mut Store<HostState>, mem: Memory, ptr: i32, data: &[u8]) -> Result<()> {
    if ptr < 0 {
        return Err(ArcError::plugin("alloc returned negative ptr"));
    }
    let off = ptr as usize;
    mem.write(store, off, data)
        .map_err(|_| ArcError::plugin("failed to write wasm memory"))?;
    Ok(())
}

/// Convenience: load wasm module from a file path, used in config compilation.
pub fn load_module(engine: &Engine, path: &Path) -> Result<Module> {
    Module::from_file(engine, path).map_err(|_| ArcError::plugin("Module::from_file failed"))
}
