use bitflags::bitflags;

pub use crate::defs::{MemoryType, Protection};

#[derive(thiserror::Error, Debug)]
pub enum EnvError {
    #[error("operation not supported: `{0}`")]
    NotSupported(anyhow::Error),
    #[error("no such process")]
    NoSuchProcess,
    #[error("read memory failed")]
    ReadMemoryFailed,
    #[error("no region found")]
    NoRegionFound,
    #[error("access outside region bounds")]
    AccessOutsideBounds,
}

#[derive(Debug, Clone)]
pub enum EnvAbi {
    Windows,
    Other,
}

#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum EnvArch {
    x86,
    x86_64,
    Arm,
    Aarch64,
}

#[derive(Debug, Clone)]
pub enum EnvPlatform {
    Windows,
    Linux,
    Android,
    Other,
}

impl EnvPlatform {
    pub fn is_android(&self) -> bool {
        matches!(self, Self::Android)
    }
}

pub type Result<T> = std::result::Result<T, EnvError>;

#[derive(Debug)]
pub struct RegionInfo {
    pub base: u64,
    pub size: u64,
    pub mem_type: MemoryType,
    pub protection: Protection,
}

bitflags! {
    #[derive(Debug)]
    pub struct FindRegionsFlags: u8 {
        const PAGED_ONLY = 1 << 0;
        const DIRTY_ONLY = 1 << 1;
        const NO_SHARED = 1 << 2;
    }
}

pub type ProcessId = u32;
pub type ThreadId = u32;

#[derive(Debug, Clone)]
pub struct ProcessDesc {
    pub name: String,
    pub pid: ProcessId,
}

#[derive(Debug, Clone)]
pub struct ModuleDesc {
    pub base: u64,
    pub size: u64,
    pub fileoffset: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ThreadDesc {
    pub thread_id: ThreadId,
}

pub trait Thread {}

pub trait Process {
    fn get_architecture(&self) -> EnvArch;

    fn read_memory(&self, base: u64, buf: &mut [u8]) -> Result<()>;

    fn write_memory(&self, base: u64, buf: &[u8]) -> Result<()>;

    fn change_memory_protection(&self, base: u64, size: u64, protection: Protection) -> Result<()>;

    fn mem_alloc(
        &self,
        preferred_base: Option<u64>,
        size: u64,
        protection: Protection,
    ) -> Result<u64>;

    fn mem_free(&self, base: u64, size: u64) -> Result<()>;

    fn query_region(&self, addr: u64) -> Result<RegionInfo>;

    fn list_regions(&self, flags: FindRegionsFlags)
        -> Result<Box<dyn Iterator<Item = RegionInfo>>>;

    fn list_modules(&self) -> Result<Box<dyn Iterator<Item = ModuleDesc>>>;

    fn list_threads(&self) -> Result<Box<dyn Iterator<Item = ThreadDesc>>>;

    fn create_thread(
        &self,
        start_address: u64,
        parameter: u64,
    ) -> Result<Box<dyn Thread + Send + Sync>>;
}

pub trait Environment {
    fn get_abi(&self) -> EnvAbi;

    fn get_platform(&self) -> EnvPlatform {
        EnvPlatform::Other
    }

    fn list_processes(&self) -> Result<Box<dyn Iterator<Item = ProcessDesc>>>;

    fn open_process(&self, pid: ProcessId) -> Result<Box<dyn Process + Send + Sync>>;

    fn list_modules(&self, pid: ProcessId) -> Result<Box<dyn Iterator<Item = ModuleDesc>>> {
        self.open_process(pid)?.list_modules()
    }

    fn list_threads(&self, pid: ProcessId) -> Result<Box<dyn Iterator<Item = ThreadDesc>>> {
        self.open_process(pid)?.list_threads()
    }
}
