use std::sync::{Arc, Mutex};

use crate::defs::{CeAbi, CeArch, MemoryType, Protection, Th32Flags};
use bitflags::bitflags;
use strum::Display;

#[derive(Display, Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u32)]
pub enum CeOption {
    MemorySearch,
    AttachToAccessMemory,
    AttachToWriteMemory,
    AllocateMemoryWithoutExtensionInjection,
}

#[derive(Debug, Clone)]
pub struct CeOptionDescription {
    pub option_id: CeOption,
    pub name: &'static str,
    pub parent: Option<&'static str>,
    pub description: &'static str,
    pub acceptable_values: Option<&'static str>,
    pub option_type: CeOptionType,
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum CeOptionType {
    Parent = 0,
    Boolean = 1,
    Int = 2,
    Float = 3,
    Double = 4,
    Text = 5,
}

pub const CE_OPTIONS: &[CeOptionDescription] = &[
    CeOptionDescription {
        option_id: CeOption::MemorySearch,
        name: "optMSO",
        parent: None,
        description: "Memory search option",
        acceptable_values: Some("0=/proc/pid/mem reads;1=ptrace read;2=process_vm_readv"),
        option_type: CeOptionType::Int,
    },
    CeOptionDescription {
        option_id: CeOption::AttachToAccessMemory,
        name: "optATAM",
        parent: None,
        description: "Attach to access memory",
        acceptable_values: None,
        option_type: CeOptionType::Boolean,
    },
    CeOptionDescription {
        option_id: CeOption::AttachToWriteMemory,
        name: "optATWM",
        parent: None,
        description: "Attach to write memory",
        acceptable_values: None,
        option_type: CeOptionType::Boolean,
    },
    CeOptionDescription {
        option_id: CeOption::AllocateMemoryWithoutExtensionInjection,
        name: "optAWSO",
        parent: None,
        description: "Allocate memory without extension injection",
        acceptable_values: None,
        option_type: CeOptionType::Boolean,
    },
];

bitflags! {
    #[derive(Debug)]
    pub struct VirtualQueryExFullFlags: u8 {
        const VQE_PAGEDONLY = 1;
        const VQE_DIRTYONLY = 2;
        const VQE_NOSHARED = 4;
    }
}

pub type CeProcessId = u32;
pub type CeThreadId = u32;
pub type CeHandle = u32;

#[derive(Debug)]
pub struct RegionInfo {
    pub base: u64,
    pub size: u64,
    pub mem_type: MemoryType,
    pub protection: Protection,
}

pub type CeAddress = u64;

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("I/O")]
    Io(#[from] std::io::Error),
    #[error("invalid handle `{0}`")]
    InvalidHandle(CeHandle),
    #[error("process not found: `{0}`")]
    ProcessNotFound(CeProcessId),
    #[error("option not found: `{0}`")]
    OptionNotFound(CeOption),
    #[error("read memory failed")]
    ReadMemoryFailed,
    #[error("no region found")]
    NoRegionFound,
    #[error("not supported: `{0}`")]
    NotSupported(anyhow::Error),
    #[error("other: `{0}`")]
    Other(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ServerError>;

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub base: u64,
    pub part: i32,
    pub size: i32,
    pub fileoffset: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ThreadEntry {
    pub thread_id: CeThreadId,
}

pub trait ResettableIterator: Iterator {
    fn reset(&mut self);
}

pub struct Tlhelp32Snapshot {
    pub processes: Box<dyn ResettableIterator<Item = ProcessEntry> + Send>,
    pub modules: Box<dyn ResettableIterator<Item = ModuleEntry> + Send>,
    pub threads: Box<dyn ResettableIterator<Item = ThreadEntry> + Send>,
}

pub trait CeServer {
    fn get_version_string(&self) -> String;

    fn get_abi(&self) -> CeAbi;

    fn terminate_server(&self);

    fn open_process(&self, pid: CeProcessId) -> Result<CeHandle>;

    fn close_handle(&self, handle: CeHandle) -> Result<()>;

    fn read_process_memory(
        &self,
        process_handle: CeHandle,
        base: CeAddress,
        size: u32,
    ) -> Result<Vec<u8>>;

    fn write_process_memory(
        &self,
        process_handle: CeHandle,
        base: CeAddress,
        buf: &[u8],
    ) -> Result<()>;

    fn change_memory_protection(
        &self,
        process_handle: CeHandle,
        base: CeAddress,
        size: usize,
        protection: Protection,
    ) -> Result<()>;

    fn get_architecture(&self, process_handle: CeHandle) -> Result<CeArch>;

    fn create_tlhelp32_snapshot(&self, flags: Th32Flags, pid: CeProcessId) -> Result<CeHandle>;

    fn get_tlhelp32_snapshot(&self, handle: CeHandle) -> Result<Arc<Mutex<Tlhelp32Snapshot>>>;

    fn list_modules(&self, pid: CeProcessId) -> Result<Vec<ModuleEntry>>;

    fn list_threads(&self, pid: CeProcessId) -> Result<Vec<ThreadEntry>>;

    fn list_processes(&self) -> Result<Vec<ProcessEntry>>;

    fn get_options(&self) -> Result<Vec<CeOptionDescription>>;

    fn get_option_value(&self, option_id: CeOption) -> Result<String>;

    fn virtual_query(&self, process_handle: CeHandle, base: CeAddress) -> Result<RegionInfo>;

    fn virtual_query_full(
        &self,
        process_handle: CeHandle,
        flags: VirtualQueryExFullFlags,
    ) -> Result<Vec<RegionInfo>>;

    fn alloc(
        &self,
        process_handle: CeHandle,
        preferred_base: CeAddress,
        size: usize,
        protection: Protection,
    ) -> Result<CeAddress>;

    fn free(&self, process_handle: CeHandle, base: CeAddress, size: usize) -> Result<()>;

    fn create_thread(
        &self,
        process_handle: CeHandle,
        start_address: CeAddress,
        parameter: u64,
    ) -> Result<CeHandle>;

    fn is_android(&self) -> bool;
}
