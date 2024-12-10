use std::{
    io::{self, Cursor, Write},
    mem::MaybeUninit,
    pin::Pin,
    sync::Arc,
};

use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    defs::{self, CeArch, Protection, Th32Flags},
    server::{CeAddress, CeHandle, CeProcessId, CeServer, ModuleEntry, VirtualQueryExFullFlags},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Ver5,
    Ver6,
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.version_number().partial_cmp(&other.version_number())
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version_number().cmp(&other.version_number())
    }
}

impl ProtocolVersion {
    pub fn is_newer_than(&self, other: ProtocolVersion) -> bool {
        self >= &other
    }

    pub fn version_number(&self) -> i32 {
        match self {
            ProtocolVersion::Ver5 => 5,
            ProtocolVersion::Ver6 => 6,
        }
    }

    pub fn has_module_fileoffset(&self) -> bool {
        match self {
            ProtocolVersion::Ver5 => false,
            ProtocolVersion::Ver6 => true,
        }
    }
}

pub trait Stream: AsyncRead + AsyncWrite {}

impl Stream for TcpStream {}

pub struct StreamConnection {
    protocol_version: ProtocolVersion,
    stream: Pin<Box<dyn Stream + Send>>,
    server: Arc<dyn CeServer + Send + Sync>,
    connection_name: String,
}

struct Reader {
    buf: Cursor<Vec<u8>>,
}

impl Reader {
    pub fn new(v: impl Into<Vec<u8>>) -> Self {
        Self {
            buf: Cursor::new(v.into()),
        }
    }

    pub fn read_handle(&mut self) -> io::Result<CeHandle> {
        self.read_u32()
    }

    pub fn read_pid(&mut self) -> io::Result<CeProcessId> {
        self.read_u32()
    }

    pub fn read_address(&mut self) -> io::Result<CeAddress> {
        self.read_u64()
    }

    pub fn read_byte(&mut self) -> io::Result<u8> {
        ReadBytesExt::read_u8(&mut self.buf)
    }

    pub fn read_u32(&mut self) -> io::Result<u32> {
        ReadBytesExt::read_u32::<LittleEndian>(&mut self.buf)
    }

    pub fn read_u64(&mut self) -> io::Result<u64> {
        ReadBytesExt::read_u64::<LittleEndian>(&mut self.buf)
    }
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn write_u16(&mut self, val: u16) {
        WriteBytesExt::write_u16::<LittleEndian>(&mut self.buf, val).unwrap();
    }

    pub fn write_i32(&mut self, val: i32) {
        WriteBytesExt::write_i32::<LittleEndian>(&mut self.buf, val).unwrap();
    }

    pub fn write_u32(&mut self, val: u32) {
        WriteBytesExt::write_u32::<LittleEndian>(&mut self.buf, val).unwrap();
    }

    pub fn write_u64(&mut self, val: u64) {
        WriteBytesExt::write_u64::<LittleEndian>(&mut self.buf, val).unwrap();
    }

    pub fn write_byte(&mut self, val: u8) {
        WriteBytesExt::write_u8(&mut self.buf, val).unwrap();
    }

    pub fn write_raw_bytes(&mut self, bytes: &[u8]) {
        Write::write_all(&mut self.buf, bytes).unwrap();
    }

    pub fn write_bytes32(&mut self, bytes: &[u8]) {
        self.write_i32(bytes.len() as i32);
        self.write_raw_bytes(bytes);
    }

    pub fn write_bytes8(&mut self, bytes: &[u8]) {
        if bytes.len() > 0xFF {
            panic!("cannot send a byte array longer than 255 bytes");
        }

        self.write_byte(bytes.len() as u8);
        self.write_raw_bytes(bytes);
    }

    pub fn write_bytes16(&mut self, bytes: &[u8]) {
        if bytes.len() > 0xFFFF {
            panic!("cannot send a byte array longer than 65535 bytes");
        }

        self.write_u16(bytes.len() as u16);
        self.write_raw_bytes(bytes);
    }

    pub fn write_handle(&mut self, handle: CeHandle) {
        self.write_u32(handle);
    }

    pub fn write_pid(&mut self, pid: CeProcessId) {
        self.write_u32(pid);
    }

    pub fn write_address(&mut self, address: CeAddress) {
        self.write_u64(address);
    }
}

impl StreamConnection {
    pub fn new(
        stream: Box<dyn Stream + Send>,
        server: Arc<dyn CeServer + Send + Sync>,
        protocol_version: ProtocolVersion,
    ) -> Self {
        Self {
            stream: Box::into_pin(stream),
            server,
            connection_name: "*".to_string(),
            protocol_version,
        }
    }

    pub async fn serve(&mut self) -> anyhow::Result<()> {
        log::debug!("Start serving.");

        loop {
            self.serve_once().await?;
        }
    }

    async fn read_bytes(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.stream.read_exact(buf).await?;
        log::trace!("Read: {:02X?}", buf);
        Ok(())
    }

    async fn read<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let mut buf: [u8; N] = unsafe { MaybeUninit::uninit().assume_init() };
        self.read_bytes(&mut buf).await?;
        Ok(buf)
    }

    async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        self.stream.write_all(buf).await?;

        if buf.len() < 0x100 {
            log::trace!("Written: {} {:X?}", buf.len(), buf);
        } else {
            log::trace!("Written: {}", buf.len());
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    pub async fn serve_once(&mut self) -> anyhow::Result<()> {
        let Ok(command) = defs::Command::try_from(self.read::<1>().await?[0]) else {
            return Err(anyhow!("unknown command"));
        };

        log::debug!("[{}] Command: {:?}", self.connection_name, command);

        self.handle_command(command).await
    }

    pub async fn handle_command(&mut self, command: defs::Command) -> anyhow::Result<()> {
        match command {
            defs::Command::GETVERSION => {
                log::debug!("GETVERSION");

                let version_string = self.server.get_version_string();
                let version_number = self.protocol_version.version_number();

                let mut writer = Writer::new();

                writer.write_i32(version_number);
                writer.write_bytes8(version_string.as_bytes());

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::CLOSECONNECTION => todo!(),
            defs::Command::TERMINATESERVER => {
                log::debug!("TERMINATESERVER");

                self.server.terminate_server();
                Ok(())
            }
            defs::Command::OPENPROCESS => {
                let mut reader = Reader::new(self.read::<4>().await?);
                let pid = reader.read_pid()?;

                log::debug!("OPENPROCESS: pid={}", pid);

                if let Some(handle) = self.server.open_process(pid).ok() {
                    let mut writer = Writer::new();
                    writer.write_handle(handle);
                    self.write(writer.as_bytes()).await?;
                    Ok(())
                } else {
                    Err(anyhow!("process not found"))
                }
            }
            defs::Command::CREATETOOLHELP32SNAPSHOT => todo!(),
            defs::Command::PROCESS32FIRST => Ok(self.process_next(true).await?),
            defs::Command::PROCESS32NEXT => Ok(self.process_next(false).await?),
            defs::Command::CLOSEHANDLE => {
                let mut reader = Reader::new(self.read::<4>().await?);
                let handle = reader.read_handle()?;

                log::debug!("CLOSEHANDLE: {}", handle,);

                if self.server.close_handle(handle).is_ok() {
                    let mut writer = Writer::new();
                    writer.write_i32(1);
                    self.write(writer.as_bytes()).await?;
                    Ok(())
                } else {
                    Err(anyhow!("invalid handle"))
                }
            }
            defs::Command::VIRTUALQUERYEX => {
                let mut reader = Reader::new(self.read::<12>().await?);
                let handle = reader.read_handle()?;
                let base = reader.read_address()?;

                log::debug!("VIRTUALQUERYEX: handle={}, base=0x{:X}", handle, base);

                let result = self.server.virtual_query(handle, base);

                let mut writer = Writer::new();

                match result {
                    Ok(mem) => {
                        writer.write_byte(1);
                        writer.write_u32(mem.protection.bits());
                        writer.write_u32(mem.mem_type.bits());
                        writer.write_u64(mem.base);
                        writer.write_u64(mem.size);
                    }
                    Err(_err) => {
                        writer.write_byte(0);
                        writer.write_u32(0);
                        writer.write_u32(0);
                        writer.write_u64(0);
                        writer.write_u64(0);
                    }
                }

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::READPROCESSMEMORY => {
                let mut reader = Reader::new(self.read::<17>().await?);
                let handle = reader.read_handle()?;
                let base = reader.read_address()?;
                let size = reader.read_u32()?;
                let compress = reader.read_byte()?;

                log::debug!(
                    "READPROCESSMEMORY: handle={}, base=0x{:X}, size=0x{:X}, compress={}",
                    handle,
                    base,
                    size,
                    compress
                );

                if compress != 0 {
                    unimplemented!();
                }

                let bytes = self
                    .server
                    .read_process_memory(handle, base, size)
                    .unwrap_or_default();

                let mut writer = Writer::new();
                writer.write_bytes32(&bytes);

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::WRITEPROCESSMEMORY => {
                let mut res = Reader::new(self.read::<16>().await?);
                let process_handle = res.read_handle()?;
                let base = res.read_address()?;
                let size = res.read_u32()? as usize;

                log::debug!(
                    "WRITEPROCESSMEMORY: handle={}, base=0x{:X}, size=0x{:X}",
                    process_handle,
                    base,
                    size
                );

                let mut success = false;

                if size > 0 {
                    let mut buf = vec![0u8; size];
                    self.read_bytes(&mut buf).await?;

                    match self.server.write_process_memory(process_handle, base, &buf) {
                        Ok(_) => {
                            success = true;
                        }
                        Err(err) => {
                            log::warn!("Could not write process memory: {}", err);
                        }
                    }
                }

                let mut writer = Writer::new();
                writer.write_u32(if success { 1 } else { 0 });

                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::STARTDEBUG => {
                let mut res = Reader::new(self.read::<4>().await?);
                let process_handle = res.read_handle()?;

                log::debug!("STARTDEBUG: handle={}", process_handle);

                let success = self.server.start_debug(process_handle).is_ok();

                let mut writer = Writer::new();
                writer.write_u32(if success { 1 } else { 0 });

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::STOPDEBUG => unimplemented!("not implemented by ceserver"),
            defs::Command::WAITFORDEBUGEVENT => {
                let mut res = Reader::new(self.read::<8>().await?);
                let process_handle = res.read_handle()?;
                let timeout = res.read_u32()?;

                log::debug!(
                    "WAITFORDEBUGEVENT: handle={}, timeout={}",
                    process_handle,
                    timeout
                );

                self.server
                    .wait_for_debug_event(
                        process_handle,
                        timeout,
                        Box::new(|_de| {
                            // TODO: send debug event to the client.

                            // Use Weak point to the connection.

                            // Since connection is async, we need to somehow enter an async block to send the data.
                            // Making the callback async is undesirable, since it would require the server
                            // to run a async task to execute it, loading the server with another dependency.
                            // So it's better to have a simple, synchronous callback.

                            // In the callback we should spawn an async task to send the data.
                            // Don't use tokio::spawn directly, instead use dependency injection,
                            // allowing the user decide how to spawn a task.

                            todo!();
                        }),
                    )
                    .map_err(|e| anyhow!("wait_for_debug_event error: {}", e))?;

                Ok(())
            }
            defs::Command::CONTINUEFROMDEBUGEVENT => todo!(),
            defs::Command::SETBREAKPOINT => todo!(),
            defs::Command::REMOVEBREAKPOINT => todo!(),
            defs::Command::SUSPENDTHREAD => todo!(),
            defs::Command::RESUMETHREAD => todo!(),
            defs::Command::GETTHREADCONTEXT => todo!(),
            defs::Command::SETTHREADCONTEXT => todo!(),
            defs::Command::GETARCHITECTURE => {
                let mut reader = Reader::new(self.read::<4>().await?);
                let handle = reader.read_handle()?;
                let architecture = self
                    .server
                    .get_architecture(handle)
                    .unwrap_or(CeArch::Invalid);

                let mut writer = Writer::new();
                writer.write_byte(architecture as u8);
                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::MODULE32FIRST => todo!(),
            defs::Command::MODULE32NEXT => todo!(),
            defs::Command::GETSYMBOLLISTFROMFILE => {
                let mut reader = Reader::new(self.read::<8>().await?);

                let fileoffset = if self.protocol_version.has_module_fileoffset() {
                    reader.read_u32()?
                } else {
                    0
                };

                let symbolpathlen = reader.read_u32()? as usize;
                let mut buf = vec![0u8; symbolpathlen];
                if symbolpathlen > 0x1000 {
                    return Err(anyhow!("symbolpathlen is too long"));
                }
                self.read_bytes(&mut buf).await?;
                let symbolpath = String::from_utf8(buf)?;

                log::debug!(
                    "GETSYMBOLLISTFROMFILE: fileoffset=0x{:X}, symbolpath={}",
                    fileoffset,
                    symbolpath
                );

                // TODO: implement
                let mut writer = Writer::new();
                writer.write_u64(0);
                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::LOADEXTENSION => todo!(),
            defs::Command::ALLOC => {
                let mut reader = Reader::new(self.read::<20>().await?);
                let process_handle = reader.read_handle()?;
                let address = reader.read_address()?;
                let size = reader.read_u32()? as usize;
                let protection = Protection::from_bits(reader.read_u32()?)
                    .ok_or_else(|| anyhow!("invalid protection"))?;

                log::debug!(
                    "ALLOC: process_handle={}, address=0x{:X}, size={:X}, protection={:?}",
                    process_handle,
                    address,
                    size,
                    protection
                );

                let result = match self.server.alloc(process_handle, address, size, protection) {
                    Ok(base) => base,
                    Err(err) => {
                        log::debug!("Could not alloc: {}", err);
                        0
                    }
                };

                let mut writer = Writer::new();
                writer.write_address(result);
                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::FREE => {
                let mut reader = Reader::new(self.read::<16>().await?);
                let process_handle = reader.read_handle()?;
                let address = reader.read_address()?;
                let size = reader.read_u32()? as usize;

                log::debug!(
                    "FREE: process_handle={}, address=0x{:X}, size={:X}",
                    process_handle,
                    address,
                    size
                );

                let result = match self.server.free(process_handle, address, size) {
                    Ok(_) => 1,
                    Err(err) => {
                        log::debug!("Could not alloc: {}", err);
                        0
                    }
                };

                let mut writer = Writer::new();
                writer.write_u32(result);
                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::CREATETHREAD => {
                let mut reader = Reader::new(self.read::<20>().await?);
                let process_handle = reader.read_handle()?;
                let start_address = reader.read_address()?;
                let parameter = reader.read_u64()?;

                log::debug!(
                    "CREATETHREAD: process_handle={}, start_address=0x{:X}, parameter={:X}",
                    process_handle,
                    start_address,
                    parameter
                );

                let handle =
                    match self
                        .server
                        .create_thread(process_handle, start_address, parameter)
                    {
                        Ok(handle) => handle,
                        Err(err) => {
                            log::debug!("Could not alloc: {}", err);
                            0
                        }
                    };

                let mut writer = Writer::new();
                writer.write_handle(handle);
                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::LOADMODULE => todo!(),
            defs::Command::SPEEDHACK_SETSPEED => todo!(),
            defs::Command::VIRTUALQUERYEXFULL => {
                let mut reader = Reader::new(self.read::<5>().await?);
                let handle = reader.read_handle()?;
                let flags = VirtualQueryExFullFlags::from_bits(reader.read_byte()?)
                    .ok_or_else(|| anyhow!("invalid VirtualQueryExFull flags"))?;

                log::debug!("VIRTUALQUERYEXFULL: handle={}, flags={:?}", handle, flags);

                let regions = self.server.virtual_query_full(handle, flags)?;

                let mut writer = Writer::new();

                writer.write_u32(regions.len() as u32);

                for region in regions {
                    log::debug!("Region: {:?}", region);
                    writer.write_address(region.base);
                    writer.write_u64(region.size);
                    writer.write_u32(region.protection.bits());
                    writer.write_u32(region.mem_type.bits());
                }

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::GETREGIONINFO => todo!(),
            defs::Command::GETABI => {
                let mut writer = Writer::new();
                writer.write_byte(self.server.get_abi() as u8);
                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::SET_CONNECTION_NAME => {
                let mut reader = Reader::new(self.read::<4>().await?);
                let name_len = reader.read_u32()?;
                if name_len > 0x1000 {
                    return Err(anyhow!("name is too long"));
                }
                let mut buf = vec![0u8; name_len as usize];
                self.read_bytes(&mut buf).await?;

                let connection_name = String::from_utf8(buf)?;

                log::info!("Updated connection name: {}", connection_name);

                self.connection_name = connection_name;

                Ok(())
            }
            defs::Command::CREATETOOLHELP32SNAPSHOTEX => {
                let mut reader = Reader::new(self.read::<8>().await?);
                let flags = Th32Flags::from_bits(reader.read_u32()?)
                    .ok_or_else(|| anyhow!("th32 dwFlags"))?;

                let pid = reader.read_u32()?;

                let mut writer = Writer::new();

                if flags.intersects(Th32Flags::TH32CS_SNAPTHREAD) {
                    let threads = self.server.list_threads(pid).unwrap_or_default();

                    writer.write_u32(threads.len() as u32);
                    threads
                        .into_iter()
                        .for_each(|te| writer.write_u32(te.thread_id));
                } else if flags.intersects(Th32Flags::TH32CS_SNAPMODULE_ANY) {
                    let modules = self.server.list_modules(pid).unwrap_or_default();

                    let mut write_module_entry = |result: i32, me: &ModuleEntry| {
                        writer.write_i32(result);
                        writer.write_address(me.base);
                        writer.write_i32(me.part);
                        writer.write_i32(me.size);
                        if self.protocol_version.has_module_fileoffset() {
                            writer.write_u32(me.fileoffset);
                        }
                        writer.write_bytes32(me.name.as_bytes());
                    };

                    for me in modules {
                        write_module_entry(1, &me);
                    }

                    write_module_entry(
                        0,
                        &ModuleEntry {
                            base: 0,
                            part: 0,
                            size: 0,
                            fileoffset: 0,
                            name: String::new(),
                        },
                    );
                } else {
                    assert!(flags == Th32Flags::TH32CS_SNAPPROCESS);

                    let handle = self.server.create_tlhelp32_snapshot(flags, pid)?;

                    writer.write_handle(handle);
                }

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::CHANGEMEMORYPROTECTION => {
                let mut reader = Reader::new(self.read::<20>().await?);
                let process_handle = reader.read_handle()?;
                let address = reader.read_address()?;
                let size = reader.read_u32()? as usize;
                let protection = Protection::from_bits(reader.read_u32()?)
                    .ok_or_else(|| anyhow!("invalid protection"))?;

                log::debug!("CHANGEMEMORYPROTECTION: process_handle={}, address=0x{:X}, size={:X}, protection={:?}", process_handle, address, size, protection);
                let mut result = -1;

                match self.server.change_memory_protection(
                    process_handle,
                    address,
                    size,
                    protection,
                ) {
                    Ok(_) => {
                        result = 0;
                    }
                    Err(err) => {
                        log::debug!("Could not change memory protection: {}", err)
                    }
                }

                let mut writer = Writer::new();
                writer.write_i32(result);
                writer.write_u32(0);
                self.write(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::GETOPTIONS => {
                let options = self.server.get_options()?;

                let mut writer = Writer::new();

                writer.write_u16(options.len() as u16);

                for option in options {
                    let opt_value = self
                        .server
                        .get_option_value(option.option_id)
                        .unwrap_or_default();
                    writer.write_bytes16(option.name.as_bytes());
                    writer.write_bytes16(option.parent.unwrap_or_default().as_bytes());
                    writer.write_bytes16(option.description.as_bytes());
                    writer.write_bytes16(option.acceptable_values.unwrap_or_default().as_bytes());
                    writer.write_bytes16(opt_value.as_str().as_bytes());
                    writer.write_i32(option.option_type as i32);
                }

                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::GETOPTIONVALUE => todo!(),
            defs::Command::SETOPTIONVALUE => todo!(),
            defs::Command::PTRACE_MMAP => todo!(),
            defs::Command::OPENNAMEDPIPE => todo!(),
            defs::Command::PIPEREAD => todo!(),
            defs::Command::PIPEWRITE => todo!(),
            defs::Command::GETCESERVERPATH => todo!(),
            defs::Command::ISANDROID => {
                let mut writer = Writer::new();
                let is_android = self.server.is_android();
                writer.write_byte(if is_android { 1 } else { 0 });
                self.write(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::LOADMODULEEX => todo!(),
            defs::Command::SETCURRENTPATH => todo!(),
            defs::Command::GETCURRENTPATH => todo!(),
            defs::Command::ENUMFILES => todo!(),
            defs::Command::GETFILEPERMISSIONS => todo!(),
            defs::Command::SETFILEPERMISSIONS => todo!(),
            defs::Command::GETFILE => todo!(),
            defs::Command::PUTFILE => todo!(),
            defs::Command::CREATEDIR => todo!(),
            defs::Command::DELETEFILE => todo!(),
            defs::Command::AOBSCAN => todo!(),
            defs::Command::COMMANDLIST2 => unimplemented!(),
        }
    }

    async fn process_next(&mut self, first: bool) -> anyhow::Result<()> {
        let mut reader = Reader::new(self.read::<4>().await?);
        let handle = reader.read_handle()?;

        let mut writer = Writer::new();

        {
            let snapshot_shared = self.server.get_tlhelp32_snapshot(handle)?;
            let mut snapshot = snapshot_shared.lock().unwrap();

            if first {
                snapshot.processes.reset();
            }

            if let Some(pe) = snapshot.processes.next() {
                writer.write_i32(1);
                writer.write_pid(pe.pid);
                writer.write_bytes32(pe.name.as_bytes());
            } else {
                writer.write_i32(0);
                writer.write_i32(0);
                writer.write_i32(0);
            }
        }

        self.write(writer.as_bytes()).await?;
        Ok(())
    }
}

// TODO: write tests
