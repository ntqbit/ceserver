use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use anyhow::anyhow;

use crate::{
    defs::{CeAbi, CeArch, Protection, Th32Flags},
    environment::{EnvAbi, EnvArch, EnvError, Environment, FindRegionsFlags, Process, Thread},
    handle::HandleAllocator,
    server::{
        self, CeHandle, CeOption, CeOptionDescription, CeProcessId, CeServer, ModuleEntry,
        ProcessEntry, RegionInfo, ResettableIterator, ServerError, ThreadEntry, Tlhelp32Snapshot,
        VirtualQueryExFullFlags, WaitForDebugEventCb, CE_OPTIONS,
    },
};

const CE_VERSION_STRING: &str = "CHEATENGINE Network 2.2";

pub enum Resource {
    TlhelpSnapshot(Arc<Mutex<Tlhelp32Snapshot>>),
    Process(Box<dyn Process + Send + Sync>),
    Thread(Box<dyn Thread + Send + Sync>),
}

#[derive(Debug)]
pub struct CursorVec<T> {
    vec: Vec<T>,
    position: usize,
}

impl<T> CursorVec<T> {
    pub fn new(vec: Vec<T>) -> Self {
        Self { vec, position: 0 }
    }
}

impl<T: Clone> Iterator for CursorVec<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.position == self.vec.len() {
            None
        } else {
            debug_assert!(self.position < self.vec.len());

            self.position += 1;
            Some(self.vec[self.position - 1].clone())
        }
    }
}

impl<T: Clone> ResettableIterator for CursorVec<T> {
    fn reset(&mut self) {
        self.position = 0;
    }
}

struct ResourceManager {
    handle_allocator: HandleAllocator<CeHandle>,
    resources: HashMap<CeHandle, Resource>,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            handle_allocator: HandleAllocator::new(),
            resources: HashMap::new(),
        }
    }

    pub fn open(&mut self, resource: Resource) -> CeHandle {
        let handle = self.handle_allocator.allocate().unwrap();
        let old = self.resources.insert(handle, resource);
        debug_assert!(old.is_none());
        debug_assert!(self.handle_allocator.is_allocated(handle));
        handle
    }

    pub fn get(&self, handle: CeHandle) -> Option<&Resource> {
        self.resources.get(&handle)
    }

    pub fn get_mut(&mut self, handle: CeHandle) -> Option<&mut Resource> {
        self.resources.get_mut(&handle)
    }

    pub fn close(&mut self, handle: CeHandle) -> Result<(), ()> {
        if self.handle_allocator.deallocate(handle).is_ok() {
            debug_assert!(!self.handle_allocator.is_allocated(handle));
            let val = self.resources.remove(&handle);
            debug_assert!(val.is_some());
            Ok(())
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone)]
enum CeOptionValue {
    Boolean(bool),
    Int(i32),
    Float(f32),
    Double(f64),
    Text(String),
}

impl ToString for CeOptionValue {
    fn to_string(&self) -> String {
        match self {
            CeOptionValue::Boolean(val) => if *val { "1" } else { "0" }.to_owned(),
            CeOptionValue::Int(val) => val.to_string(),
            CeOptionValue::Float(val) => val.to_string(),
            CeOptionValue::Double(val) => val.to_string(),
            CeOptionValue::Text(val) => val.clone(),
        }
    }
}

pub struct EnvironmentServer {
    resources: RwLock<ResourceManager>,
    options: HashMap<CeOption, CeOptionValue>,
    env: Box<dyn Environment + Send + Sync>,
}

impl EnvironmentServer {
    pub fn new(env: Box<dyn Environment + Send + Sync>) -> Self {
        let options_list = [
            (CeOption::MemorySearch, CeOptionValue::Int(0)),
            (
                CeOption::AttachToAccessMemory,
                CeOptionValue::Boolean(false),
            ),
            (CeOption::AttachToWriteMemory, CeOptionValue::Boolean(true)),
            (
                CeOption::AllocateMemoryWithoutExtensionInjection,
                CeOptionValue::Boolean(false),
            ),
        ];
        let options = HashMap::from_iter(options_list.into_iter());

        Self {
            resources: RwLock::new(ResourceManager::new()),
            options,
            env,
        }
    }
}

impl CeServer for EnvironmentServer {
    fn get_version_string(&self) -> String {
        CE_VERSION_STRING.to_string()
    }

    fn get_abi(&self) -> CeAbi {
        match self.env.get_abi() {
            EnvAbi::Windows => CeAbi::Windows,
            EnvAbi::Other => CeAbi::Other,
        }
    }

    fn terminate_server(&self) {
        // TODO: should we actually terminate the server?
    }

    fn open_process(&self, pid: CeProcessId) -> server::Result<CeHandle> {
        match self.env.open_process(pid) {
            Ok(process) => Ok(self
                .resources
                .write()
                .unwrap()
                .open(Resource::Process(process))),
            Err(EnvError::NoSuchProcess) => Err(ServerError::ProcessNotFound(pid)),
            Err(err) => Err(ServerError::Other(anyhow::Error::new(err))),
        }
    }

    fn close_handle(&self, handle: CeHandle) -> server::Result<()> {
        self.resources
            .write()
            .unwrap()
            .close(handle)
            .map_err(|_| ServerError::InvalidHandle(handle))
    }

    fn read_process_memory(
        &self,
        process_handle: CeHandle,
        base: server::CeAddress,
        size: u32,
    ) -> server::Result<Vec<u8>> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        let mut buf = vec![0u8; size as usize];

        match process.read_memory(base, &mut buf) {
            Ok(_) => Ok(buf),
            Err(err) => Err(ServerError::Other(anyhow::Error::new(err))),
        }
    }

    fn write_process_memory(
        &self,
        process_handle: CeHandle,
        base: server::CeAddress,
        buf: &[u8],
    ) -> server::Result<()> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        match process.write_memory(base, buf) {
            Ok(_) => Ok(()),
            Err(err) => Err(ServerError::Other(anyhow::Error::new(err))),
        }
    }

    fn change_memory_protection(
        &self,
        process_handle: CeHandle,
        base: server::CeAddress,
        size: usize,
        protection: Protection,
    ) -> server::Result<()> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        process
            .change_memory_protection(base, size as u64, protection)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?;

        Ok(())
    }

    fn get_architecture(&self, process_handle: CeHandle) -> server::Result<CeArch> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        Ok(match process.get_architecture() {
            EnvArch::x86 => CeArch::x86,
            EnvArch::x86_64 => CeArch::x86_64,
            EnvArch::Arm => CeArch::Arm,
            EnvArch::Aarch64 => CeArch::Aarch64,
        })
    }

    fn list_modules(&self, pid: CeProcessId) -> server::Result<Vec<ModuleEntry>> {
        Ok(self
            .env
            .list_modules(pid)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?
            .map(|me| ModuleEntry {
                base: me.base,
                part: 0, // TODO: fix
                size: me.size as i32,
                fileoffset: me.fileoffset as u32,
                name: me.name,
            })
            .collect())
    }

    fn list_processes(&self) -> server::Result<Vec<ProcessEntry>> {
        Ok(self
            .env
            .list_processes()
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?
            .map(|pe| ProcessEntry {
                pid: pe.pid,
                name: pe.name,
            })
            .collect())
    }

    fn list_threads(&self, pid: CeProcessId) -> server::Result<Vec<ThreadEntry>> {
        Ok(self
            .env
            .list_threads(pid)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?
            .map(|te| ThreadEntry {
                thread_id: te.thread_id,
            })
            .collect())
    }

    fn create_tlhelp32_snapshot(
        &self,
        flags: Th32Flags,
        pid: server::CeProcessId,
    ) -> server::Result<CeHandle> {
        // Collect processes.
        let processes = if flags.contains(Th32Flags::TH32CS_SNAPPROCESS) {
            self.list_processes()?
        } else {
            Vec::new()
        };

        let modules = if flags.intersects(Th32Flags::TH32CS_SNAPMODULE_ANY) {
            self.list_modules(pid)?
        } else {
            Vec::new()
        };

        let threads = if flags.intersects(Th32Flags::TH32CS_SNAPTHREAD) {
            self.list_threads(pid)?
        } else {
            Vec::new()
        };

        let snapshot = Arc::new(Mutex::new(Tlhelp32Snapshot {
            processes: Box::new(CursorVec::new(processes)),
            modules: Box::new(CursorVec::new(modules)),
            threads: Box::new(CursorVec::new(threads)),
        }));

        Ok(self
            .resources
            .write()
            .unwrap()
            .open(Resource::TlhelpSnapshot(snapshot)))
    }

    fn get_tlhelp32_snapshot(
        &self,
        handle: CeHandle,
    ) -> server::Result<Arc<Mutex<server::Tlhelp32Snapshot>>> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::TlhelpSnapshot(snap)) = resources.get(handle) else {
            return Err(ServerError::InvalidHandle(handle));
        };

        Ok(snap.clone())
    }

    fn get_options(&self) -> server::Result<Vec<CeOptionDescription>> {
        Ok(CE_OPTIONS
            .into_iter()
            .filter(|opt| self.options.contains_key(&opt.option_id))
            .cloned()
            .collect())
    }

    fn get_option_value(&self, option_id: CeOption) -> server::Result<String> {
        let Some(option_value) = self.options.get(&option_id) else {
            return Err(ServerError::OptionNotFound(option_id));
        };

        Ok(option_value.to_string())
    }

    fn virtual_query(
        &self,
        process_handle: CeHandle,
        base: server::CeAddress,
    ) -> server::Result<RegionInfo> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        let ri = process
            .query_region(base)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?;

        Ok(RegionInfo {
            base: ri.base,
            size: ri.size,
            mem_type: ri.mem_type,
            protection: ri.protection,
        })
    }

    fn virtual_query_full(
        &self,
        process_handle: CeHandle,
        flags: VirtualQueryExFullFlags,
    ) -> server::Result<Vec<RegionInfo>> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        let regions = process
            .list_regions(to_find_regions_flags(flags))
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?;

        Ok(regions
            .into_iter()
            .map(|ri| RegionInfo {
                base: ri.base,
                size: ri.size,
                mem_type: ri.mem_type,
                protection: ri.protection,
            })
            .collect())
    }

    fn alloc(
        &self,
        process_handle: CeHandle,
        preferred_base: server::CeAddress,
        size: usize,
        protection: Protection,
    ) -> server::Result<server::CeAddress> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        let preferred_base_opt = if preferred_base != 0 {
            Some(preferred_base)
        } else {
            None
        };

        process
            .mem_alloc(preferred_base_opt, size as u64, protection)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))
    }

    fn free(
        &self,
        process_handle: CeHandle,
        base: server::CeAddress,
        size: usize,
    ) -> server::Result<()> {
        let resources = self.resources.read().unwrap();

        let Some(Resource::Process(process)) = resources.get(process_handle) else {
            return Err(ServerError::InvalidHandle(process_handle));
        };

        process
            .mem_free(base, size as u64)
            .map_err(|err| ServerError::Other(anyhow::Error::new(err)))
    }

    fn is_android(&self) -> bool {
        self.env.get_platform().is_android()
    }

    fn create_thread(
        &self,
        process_handle: CeHandle,
        start_address: server::CeAddress,
        parameter: u64,
    ) -> server::Result<CeHandle> {
        let thread = {
            let resources = self.resources.read().unwrap();

            let Some(Resource::Process(process)) = resources.get(process_handle) else {
                return Err(ServerError::InvalidHandle(process_handle));
            };

            process
                .create_thread(start_address, parameter)
                .map_err(|err| ServerError::Other(anyhow::Error::new(err)))?
        };

        Ok(self
            .resources
            .write()
            .unwrap()
            .open(Resource::Thread(thread)))
    }

    fn start_debug(&self, _process_handle: CeHandle) -> server::Result<()> {
        // TODO: implement
        Err(server::ServerError::Other(anyhow!(
            "could not start debugger"
        )))
    }

    fn wait_for_debug_event(
        &self,
        _process_handle: CeHandle,
        _timeout: u32,
        _cb: WaitForDebugEventCb,
    ) -> server::Result<()> {
        Ok(())
    }
}

fn to_find_regions_flags(flags: VirtualQueryExFullFlags) -> FindRegionsFlags {
    FindRegionsFlags::from_bits(flags.bits()).unwrap()
}
