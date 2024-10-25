#![allow(non_camel_case_types, unused)]

use bitflags::bitflags;

#[derive(Debug, num_enum::TryFromPrimitive)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Command {
    GETVERSION = 0,
    CLOSECONNECTION = 1,
    TERMINATESERVER = 2,
    OPENPROCESS = 3,
    CREATETOOLHELP32SNAPSHOT = 4,
    PROCESS32FIRST = 5,
    PROCESS32NEXT = 6,
    CLOSEHANDLE = 7,
    VIRTUALQUERYEX = 8,
    READPROCESSMEMORY = 9,
    WRITEPROCESSMEMORY = 10,
    STARTDEBUG = 11,
    STOPDEBUG = 12,
    WAITFORDEBUGEVENT = 13,
    CONTINUEFROMDEBUGEVENT = 14,
    SETBREAKPOINT = 15,
    REMOVEBREAKPOINT = 16,
    SUSPENDTHREAD = 17,
    RESUMETHREAD = 18,
    GETTHREADCONTEXT = 19,
    SETTHREADCONTEXT = 20,
    GETARCHITECTURE = 21,
    MODULE32FIRST = 22,
    MODULE32NEXT = 23,
    GETSYMBOLLISTFROMFILE = 24,
    LOADEXTENSION = 25,
    ALLOC = 26,
    FREE = 27,
    CREATETHREAD = 28,
    LOADMODULE = 29,
    SPEEDHACK_SETSPEED = 30,
    VIRTUALQUERYEXFULL = 31,
    GETREGIONINFO = 32,
    GETABI = 33,
    SET_CONNECTION_NAME = 34,
    CREATETOOLHELP32SNAPSHOTEX = 35,
    CHANGEMEMORYPROTECTION = 36,
    GETOPTIONS = 37,
    GETOPTIONVALUE = 38,
    SETOPTIONVALUE = 39,
    PTRACE_MMAP = 40,
    OPENNAMEDPIPE = 41,
    PIPEREAD = 42,
    PIPEWRITE = 43,
    GETCESERVERPATH = 44,
    ISANDROID = 45,
    LOADMODULEEX = 46,
    SETCURRENTPATH = 47,
    GETCURRENTPATH = 48,
    ENUMFILES = 49,
    GETFILEPERMISSIONS = 50,
    SETFILEPERMISSIONS = 51,
    GETFILE = 52,
    PUTFILE = 53,
    CREATEDIR = 54,
    DELETEFILE = 55,
    AOBSCAN = 200,
    COMMANDLIST2 = 255,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Th32Flags: u32 {
        const TH32CS_SNAPPROCESS = 0x2;
        const TH32CS_SNAPTHREAD = 0x4;
        const TH32CS_SNAPMODULE = 0x8;
        const TH32CS_SNAPMODULE32 = 0x10;
        const TH32CS_SNAPFIRSTMODULE = 0x40000000;

        const TH32CS_SNAPMODULE_ANY = Self::TH32CS_SNAPMODULE.bits() | Self::TH32CS_SNAPMODULE32.bits();
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryType: u32 {
        const MEM_IMAGE = 0x1000000;
        const MEM_MAPPED = 0x40000;
        const MEM_PRIVATE = 0x20000;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Protection: u32 {
        const PAGE_NOACCESS           = 0x01;
        const PAGE_READONLY           = 0x02;
        const PAGE_READWRITE          = 0x04;
        const PAGE_WRITECOPY          = 0x08;
        const PAGE_EXECUTE            = 0x10;
        const PAGE_EXECUTE_READ       = 0x20;
        const PAGE_EXECUTE_READWRITE  = 0x40;
        const PAGE_EXECUTE_WRITECOPY  = 0x80;
        const ACCESS_MASK             = 0xff;
        const PAGE_GUARD              = 0x100;
        const PAGE_NOCACHE            = 0x200;
        const PAGE_WRITECOMBINE       = 0x400;
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum CeArch {
    Invalid = 0xFF,
    x86 = 0,
    x86_64 = 1,
    Arm = 2,
    Aarch64 = 3,
}

#[derive(Debug)]
#[repr(u8)]
pub enum CeAbi {
    Windows = 0,
    Other = 1,
}
