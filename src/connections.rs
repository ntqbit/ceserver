use std::{borrow::Cow, fmt::Debug, io::Read};

use anyhow::anyhow;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    defs::{self, CeArch, Protection, Th32Flags},
    messages::{
        deserialize, serialize, EmptyResponse, GetVersionResponse, OpenProcessRequest,
        OpenProcessResponse, Reader, TerminateServerResponse, Writer,
    },
    server::{CeServer, ModuleEntry, VirtualQueryExFullFlags},
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

pub struct StreamConnection<R, W, S> {
    reader: R,
    writer: W,
    server: S,
    protocol_version: ProtocolVersion,
    connection_name: Cow<'static, str>,
    connection_id: Cow<'static, str>,
}

impl<R, W, S> StreamConnection<R, W, S> {
    const INITIAL_CONNECTION_NAME: &str = "*";
    const DEFAULT_CONNECTION_ID: &str = "*";

    pub fn new(reader: R, writer: W, server: S, protocol_version: ProtocolVersion) -> Self {
        Self {
            reader,
            writer,
            server,
            connection_name: Cow::Borrowed(Self::INITIAL_CONNECTION_NAME),
            connection_id: Cow::Borrowed(Self::DEFAULT_CONNECTION_ID),
            protocol_version,
        }
    }

    pub fn set_connection_id(&mut self, connection_id: Cow<'static, str>) {
        self.connection_id = connection_id;
    }
}

impl<R, W, S> StreamConnection<R, W, S>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: CeServer,
{
    pub async fn serve(&mut self) -> anyhow::Result<()> {
        log::debug!("Start serving.");

        loop {
            self.serve_once().await?;
        }
    }

    async fn read_bytes(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.reader.read_exact(buf).await?;
        log::trace!("Read: {:02X?}", buf);
        Ok(())
    }

    async fn read_raw<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let mut buf: [u8; N] = [0; N];
        self.read_bytes(&mut buf).await?;
        Ok(buf)
    }

    async fn read<T: Debug + DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        let mut buf = [0; 4096];
        let length = self.reader.read(&mut buf).await?;
        let data = &buf[..length];
        let req = deserialize(data)?;
        log::debug!("Request: {:?}", req);
        Ok(req)
    }

    async fn write_raw(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        self.writer.write_all(buf).await?;

        if buf.len() < 0x100 {
            log::trace!("Written: {} {:X?}", buf.len(), buf);
        } else {
            log::trace!("Written: {}", buf.len());
        }

        Ok(())
    }

    async fn respond<T: Debug + Serialize>(&mut self, value: T) -> anyhow::Result<()> {
        log::debug!("Response: {:?}", value);

        self.write_raw(&serialize(&value)?).await
    }

    pub async fn serve_once(&mut self) -> anyhow::Result<()> {
        let Ok(command) = defs::Command::try_from(self.read_raw::<1>().await?[0]) else {
            return Err(anyhow!("unknown command"));
        };

        log::debug!(
            "[{}] [{}] Command: {:?}",
            self.connection_id,
            self.connection_name,
            command
        );

        self.handle_command(command).await
    }

    pub async fn handle_command(&mut self, command: defs::Command) -> anyhow::Result<()> {
        match command {
            defs::Command::GETVERSION => {
                log::debug!("GETVERSION");

                self.respond(GetVersionResponse::new(
                    self.protocol_version.version_number(),
                    self.server.get_version_string(),
                ))
                .await
            }
            defs::Command::CLOSECONNECTION => todo!(),
            defs::Command::TERMINATESERVER => {
                log::debug!("TERMINATESERVER");

                self.server.terminate_server();

                self.respond(TerminateServerResponse::new()).await
            }
            defs::Command::OPENPROCESS => {
                let req: OpenProcessRequest = self.read().await?;

                if let Some(process_handle) = self.server.open_process(req.process_id).ok() {
                    self.respond(OpenProcessResponse { process_handle }).await
                } else {
                    Err(anyhow!("process not found"))
                }
            }
            defs::Command::CREATETOOLHELP32SNAPSHOT => todo!(),
            defs::Command::PROCESS32FIRST => Ok(self.process_next(true).await?),
            defs::Command::PROCESS32NEXT => Ok(self.process_next(false).await?),
            defs::Command::CLOSEHANDLE => {
                let mut reader = Reader::new(self.read_raw::<4>().await?);
                let handle = reader.read_handle()?;

                log::debug!("CLOSEHANDLE: {}", handle,);

                if self.server.close_handle(handle).is_ok() {
                    let mut writer = Writer::new();
                    writer.write_i32(1);
                    self.write_raw(writer.as_bytes()).await?;
                    Ok(())
                } else {
                    Err(anyhow!("invalid handle"))
                }
            }
            defs::Command::VIRTUALQUERYEX => {
                let mut reader = Reader::new(self.read_raw::<12>().await?);
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

                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::READPROCESSMEMORY => {
                let mut reader = Reader::new(self.read_raw::<17>().await?);
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

                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::WRITEPROCESSMEMORY => {
                let mut res = Reader::new(self.read_raw::<16>().await?);
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

                self.write_raw(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::STARTDEBUG => {
                let mut res = Reader::new(self.read_raw::<4>().await?);
                let process_handle = res.read_handle()?;

                log::debug!("STARTDEBUG: handle={}", process_handle);

                let success = self.server.start_debug(process_handle).is_ok();

                let mut writer = Writer::new();
                writer.write_u32(if success { 1 } else { 0 });

                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::STOPDEBUG => unimplemented!("not implemented by ceserver"),
            defs::Command::WAITFORDEBUGEVENT => {
                let mut res = Reader::new(self.read_raw::<8>().await?);
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
                let mut reader = Reader::new(self.read_raw::<4>().await?);
                let handle = reader.read_handle()?;
                let architecture = self
                    .server
                    .get_architecture(handle)
                    .unwrap_or(CeArch::Invalid);

                let mut writer = Writer::new();
                writer.write_byte(architecture as u8);
                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::MODULE32FIRST => todo!(),
            defs::Command::MODULE32NEXT => todo!(),
            defs::Command::GETSYMBOLLISTFROMFILE => {
                let mut reader = Reader::new(self.read_raw::<8>().await?);

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
                self.write_raw(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::LOADEXTENSION => todo!(),
            defs::Command::ALLOC => {
                let mut reader = Reader::new(self.read_raw::<20>().await?);
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
                self.write_raw(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::FREE => {
                let mut reader = Reader::new(self.read_raw::<16>().await?);
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
                self.write_raw(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::CREATETHREAD => {
                let mut reader = Reader::new(self.read_raw::<20>().await?);
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
                self.write_raw(writer.as_bytes()).await?;

                Ok(())
            }
            defs::Command::LOADMODULE => todo!(),
            defs::Command::SPEEDHACK_SETSPEED => todo!(),
            defs::Command::VIRTUALQUERYEXFULL => {
                let mut reader = Reader::new(self.read_raw::<5>().await?);
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

                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::GETREGIONINFO => todo!(),
            defs::Command::GETABI => {
                let mut writer = Writer::new();
                writer.write_byte(self.server.get_abi() as u8);
                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::SET_CONNECTION_NAME => {
                let mut reader = Reader::new(self.read_raw::<4>().await?);
                let name_len = reader.read_u32()?;
                if name_len > 0x1000 {
                    return Err(anyhow!("name is too long"));
                }
                let mut buf = vec![0u8; name_len as usize];
                self.read_bytes(&mut buf).await?;

                let connection_name = String::from_utf8(buf)?;

                log::info!("Updated connection name: {}", connection_name);

                self.connection_name = Cow::Owned(connection_name);

                Ok(())
            }
            defs::Command::CREATETOOLHELP32SNAPSHOTEX => {
                let mut reader = Reader::new(self.read_raw::<8>().await?);
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

                self.write_raw(writer.as_bytes()).await?;
                Ok(())
            }
            defs::Command::CHANGEMEMORYPROTECTION => {
                let mut reader = Reader::new(self.read_raw::<20>().await?);
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
                self.write_raw(writer.as_bytes()).await?;

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

                self.write_raw(writer.as_bytes()).await?;
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
                self.write_raw(writer.as_bytes()).await?;
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
        let mut reader = Reader::new(self.read_raw::<4>().await?);
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

        self.write_raw(writer.as_bytes()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::Poll,
    };

    use hex_literal::hex;

    use crate::{
        connections::ProtocolVersion,
        server::{CeServer, CE_VERSION_STRING},
    };

    use super::StreamConnection;

    struct InputStream<'a>(io::Cursor<&'a [u8]>);

    impl<'a> super::AsyncRead for InputStream<'a> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let pos = self.0.position() as usize;
            let slice: &[u8] = self.0.get_ref();
            let remaining = slice.len() - pos;

            if remaining == 0 {
                // No more data. Simulate connection reset.
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
            }

            let read_len = buf.remaining();
            let start = pos as usize;
            let min_read_len = std::cmp::min(read_len, remaining);
            let end = start + min_read_len;
            buf.put_slice(&slice[start..end]);
            self.0.set_position(end as u64);
            Poll::Ready(Ok(()))
        }
    }

    fn run_connection(
        input: &'static [u8],
        server: impl CeServer,
        protocol_version: ProtocolVersion,
    ) -> Vec<u8> {
        let mut output = Vec::new();
        let reader = InputStream(io::Cursor::new(input));
        let mut connection = StreamConnection::new(reader, &mut output, server, protocol_version);

        let _result = futures::executor::block_on(connection.serve())
            // It always returns an error.
            .unwrap_err();

        // TODO: check the result. it should return ConnectionReset.

        output
    }

    fn test_input_output(
        input: &'static [u8],
        expected_output: &[u8],
        server: impl CeServer,
        protocol_version: ProtocolVersion,
    ) {
        let output = run_connection(input, server, protocol_version);
        assert_eq!(
            output, expected_output,
            "output mismatch. expected: {:02X?}, actual: {:02X?}",
            expected_output, output
        );
    }

    fn mock_server() -> impl CeServer {
        MockServer::new()
    }

    struct MockServer {}

    impl MockServer {
        pub fn new() -> Self {
            Self {}
        }
    }

    #[allow(unused)]
    impl CeServer for MockServer {
        fn get_version_string(&self) -> String {
            CE_VERSION_STRING.to_string()
        }

        fn get_abi(&self) -> crate::defs::CeAbi {
            todo!()
        }

        fn terminate_server(&self) {
            todo!()
        }

        fn open_process(
            &self,
            pid: crate::server::CeProcessId,
        ) -> crate::server::Result<crate::server::CeHandle> {
            todo!()
        }

        fn close_handle(&self, handle: crate::server::CeHandle) -> crate::server::Result<()> {
            todo!()
        }

        fn read_process_memory(
            &self,
            process_handle: crate::server::CeHandle,
            base: crate::server::CeAddress,
            size: u32,
        ) -> crate::server::Result<Vec<u8>> {
            todo!()
        }

        fn write_process_memory(
            &self,
            process_handle: crate::server::CeHandle,
            base: crate::server::CeAddress,
            buf: &[u8],
        ) -> crate::server::Result<()> {
            todo!()
        }

        fn change_memory_protection(
            &self,
            process_handle: crate::server::CeHandle,
            base: crate::server::CeAddress,
            size: usize,
            protection: crate::defs::Protection,
        ) -> crate::server::Result<()> {
            todo!()
        }

        fn get_architecture(
            &self,
            process_handle: crate::server::CeHandle,
        ) -> crate::server::Result<crate::defs::CeArch> {
            todo!()
        }

        fn create_tlhelp32_snapshot(
            &self,
            flags: crate::defs::Th32Flags,
            pid: crate::server::CeProcessId,
        ) -> crate::server::Result<crate::server::CeHandle> {
            todo!()
        }

        fn get_tlhelp32_snapshot(
            &self,
            handle: crate::server::CeHandle,
        ) -> crate::server::Result<Arc<Mutex<crate::server::Tlhelp32Snapshot>>> {
            todo!()
        }

        fn list_modules(
            &self,
            pid: crate::server::CeProcessId,
        ) -> crate::server::Result<Vec<crate::server::ModuleEntry>> {
            todo!()
        }

        fn list_threads(
            &self,
            pid: crate::server::CeProcessId,
        ) -> crate::server::Result<Vec<crate::server::ThreadEntry>> {
            todo!()
        }

        fn list_processes(&self) -> crate::server::Result<Vec<crate::server::ProcessEntry>> {
            todo!()
        }

        fn get_options(&self) -> crate::server::Result<Vec<crate::server::CeOptionDescription>> {
            todo!()
        }

        fn get_option_value(
            &self,
            option_id: crate::server::CeOption,
        ) -> crate::server::Result<String> {
            todo!()
        }

        fn virtual_query(
            &self,
            process_handle: crate::server::CeHandle,
            base: crate::server::CeAddress,
        ) -> crate::server::Result<crate::server::RegionInfo> {
            todo!()
        }

        fn virtual_query_full(
            &self,
            process_handle: crate::server::CeHandle,
            flags: crate::server::VirtualQueryExFullFlags,
        ) -> crate::server::Result<Vec<crate::server::RegionInfo>> {
            todo!()
        }

        fn alloc(
            &self,
            process_handle: crate::server::CeHandle,
            preferred_base: crate::server::CeAddress,
            size: usize,
            protection: crate::defs::Protection,
        ) -> crate::server::Result<crate::server::CeAddress> {
            todo!()
        }

        fn free(
            &self,
            process_handle: crate::server::CeHandle,
            base: crate::server::CeAddress,
            size: usize,
        ) -> crate::server::Result<()> {
            todo!()
        }

        fn create_thread(
            &self,
            process_handle: crate::server::CeHandle,
            start_address: crate::server::CeAddress,
            parameter: u64,
        ) -> crate::server::Result<crate::server::CeHandle> {
            todo!()
        }

        fn is_android(&self) -> bool {
            todo!()
        }

        fn start_debug(
            &self,
            process_handle: crate::server::CeHandle,
        ) -> crate::server::Result<()> {
            todo!()
        }

        fn wait_for_debug_event(
            &self,
            process_handle: crate::server::CeHandle,
            timeout: u32,
            cb: crate::server::WaitForDebugEventCb,
        ) -> crate::server::Result<()> {
            todo!()
        }
    }

    #[test]
    fn test_get_version() {
        const OUTPUT: &[u8] = &hex!("05000000174348454154454e47494e45204e6574776f726b20322e32");
        test_input_output(&hex!("00"), OUTPUT, mock_server(), ProtocolVersion::Ver5);
    }
}
