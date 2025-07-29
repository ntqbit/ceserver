use std::{borrow::Cow, fmt::Debug};

use anyhow::anyhow;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    defs::{self, CeArch, Protection, Th32Flags},
    messages::{
        deserialize, serialize, AllocRequest, AllocResponse, ChangeMemoryProtectionRequest,
        ChangeMemoryProtectionResponse, CloseHandleRequest, CloseHandleResponse,
        CreateThreadRequest, CreateThreadResponse, CreateToolhelp32SnapshotModulesResponse5,
        CreateToolhelp32SnapshotModulesResponse6, CreateToolhelp32SnapshotProcessResponse,
        CreateToolhelp32SnapshotRequest, CreateToolhelp32SnapshotThreadsResponse, Deserialize,
        FreeRequest, FreeResponse, GetAbiResponse, GetArchitectureRequest, GetArchitectureResponse,
        GetOptionsResponse, GetSymbolListFromFileRequest5, GetSymbolListFromFileRequest6,
        GetSymbolListFromFileResponse, GetVersionResponse, IsAndroidResponse, LoadModuleRequest,
        LoadModuleResponse, ModuleResponse5, ModuleResponse6, OpenProcessRequest,
        OpenProcessResponse, OptionResponse, Process32NextRequest, Process32NextResponse,
        ReadProcessMemoryRequest, ReadProcessMemoryResponse, RegionResponse, Serialize,
        SetConnectionNameRequest, SetConnectionNameResponse, StartDebugRequest, StartDebugResponse,
        TerminateServerResponse, VirtualQueryExFullRequest, VirtualQueryExFullResponse,
        VirtualQueryExRequest, VirtualQueryExResponse, WaitForDebugEventRequest,
        WaitForDebugEventResponse, WriteProcessMemoryRequest, WriteProcessMemoryResponse,
    },
    server::{CeServer, VirtualQueryExFullFlags},
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
    pub fn version_number(&self) -> i32 {
        match self {
            ProtocolVersion::Ver5 => 5,
            ProtocolVersion::Ver6 => 6,
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

    async fn read_buf(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.reader.read_exact(buf).await?;
        log::trace!("Read: {:02X?}", buf);
        Ok(())
    }

    async fn read_bytes<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let mut buf: [u8; N] = [0; N];
        self.read_buf(&mut buf).await?;
        Ok(buf)
    }

    async fn read<T: Debug + Deserialize>(&mut self) -> anyhow::Result<T> {
        let req = deserialize(&mut self.reader).await?;
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
        let Ok(command) = defs::Command::try_from(self.read_bytes::<1>().await?[0]) else {
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

                let process_handle =
                    if let Some(process_handle) = self.server.open_process(req.process_id).ok() {
                        process_handle
                    } else {
                        0
                    };

                self.respond(OpenProcessResponse { process_handle }).await
            }
            defs::Command::CREATETOOLHELP32SNAPSHOT => todo!(),
            defs::Command::PROCESS32FIRST => Ok(self.process_next(true).await?),
            defs::Command::PROCESS32NEXT => Ok(self.process_next(false).await?),
            defs::Command::CLOSEHANDLE => {
                let req: CloseHandleRequest = self.read().await?;

                if self.server.close_handle(req.handle).is_err() {
                    log::warn!("failed to close handle");
                }

                self.respond(CloseHandleResponse { status: 1 }).await
            }
            defs::Command::VIRTUALQUERYEX => {
                let req: VirtualQueryExRequest = self.read().await?;

                let result = self.server.virtual_query(req.process_handle, req.base);

                let response = match result {
                    Ok(mem) => VirtualQueryExResponse {
                        status: 1,
                        protection: mem.protection.bits(),
                        mem_type: mem.mem_type.bits(),
                        base: mem.base,
                        size: mem.size,
                    },
                    Err(_err) => VirtualQueryExResponse {
                        status: 0,
                        protection: 0,
                        mem_type: 0,
                        base: 0,
                        size: 0,
                    },
                };

                self.respond(response).await
            }
            defs::Command::READPROCESSMEMORY => {
                let req: ReadProcessMemoryRequest = self.read().await?;

                if req.compress != 0 {
                    // Compression is not yet implemented
                    // But it's okay, it's rarely used
                    unimplemented!();
                }

                let bytes = self
                    .server
                    .read_process_memory(req.process_handle, req.base, req.size)
                    .unwrap_or_default();

                self.respond(ReadProcessMemoryResponse { data: bytes.into() })
                    .await
            }
            defs::Command::WRITEPROCESSMEMORY => {
                let req: WriteProcessMemoryRequest = self.read().await?;

                let mut success = false;

                let data = req.data.into_inner();

                if !data.is_empty() {
                    match self
                        .server
                        .write_process_memory(req.process_handle, req.base, &data)
                    {
                        Ok(_) => {
                            success = true;
                        }
                        Err(err) => {
                            log::warn!("Could not write process memory: {}", err);
                        }
                    }
                }

                self.respond(WriteProcessMemoryResponse {
                    status: if success { 1 } else { 0 },
                })
                .await
            }
            defs::Command::STARTDEBUG => {
                let req: StartDebugRequest = self.read().await?;

                let success = self.server.start_debug(req.process_handle).is_ok();

                self.respond(StartDebugResponse {
                    status: if success { 1 } else { 0 },
                })
                .await
            }
            defs::Command::STOPDEBUG => unimplemented!("not implemented by ceserver"),
            defs::Command::WAITFORDEBUGEVENT => {
                let req: WaitForDebugEventRequest = self.read().await?;

                self.server
                    .wait_for_debug_event(
                        req.process_handle,
                        req.timeout,
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

                self.respond(WaitForDebugEventResponse::new()).await
            }
            defs::Command::CONTINUEFROMDEBUGEVENT => todo!(),
            defs::Command::SETBREAKPOINT => todo!(),
            defs::Command::REMOVEBREAKPOINT => todo!(),
            defs::Command::SUSPENDTHREAD => todo!(),
            defs::Command::RESUMETHREAD => todo!(),
            defs::Command::GETTHREADCONTEXT => todo!(),
            defs::Command::SETTHREADCONTEXT => todo!(),
            defs::Command::GETARCHITECTURE => {
                let req: GetArchitectureRequest = self.read().await?;
                let architecture = self
                    .server
                    .get_architecture(req.process_handle)
                    .unwrap_or(CeArch::Invalid);

                self.respond(GetArchitectureResponse {
                    architecture: architecture as u8,
                })
                .await
            }
            defs::Command::MODULE32FIRST => todo!(),
            defs::Command::MODULE32NEXT => todo!(),
            defs::Command::GETSYMBOLLISTFROMFILE => {
                let req: GetSymbolListFromFileRequest6 = match self.protocol_version {
                    ProtocolVersion::Ver5 => {
                        self.read::<GetSymbolListFromFileRequest5>().await?.into()
                    }
                    ProtocolVersion::Ver6 => self.read().await?,
                };
                let _symbolpath = String::from_utf8(req.symbolpath.into_inner())?;

                // TODO: implement

                self.respond(GetSymbolListFromFileResponse { result: 0 })
                    .await
            }
            defs::Command::LOADEXTENSION => todo!(),
            defs::Command::ALLOC => {
                let req: AllocRequest = self.read().await?;
                let protection = Protection::from_bits(req.protection)
                    .ok_or_else(|| anyhow!("invalid protection"))?;

                let result = match self.server.alloc(
                    req.process_handle,
                    req.address,
                    req.size as usize,
                    protection,
                ) {
                    Ok(base) => base,
                    Err(err) => {
                        log::debug!("Could not alloc: {}", err);
                        0
                    }
                };

                self.respond(AllocResponse { address: result }).await
            }
            defs::Command::FREE => {
                let req: FreeRequest = self.read().await?;

                let result =
                    match self
                        .server
                        .free(req.process_handle, req.address, req.size as usize)
                    {
                        Ok(_) => 1,
                        Err(err) => {
                            log::debug!("Could not alloc: {}", err);
                            0
                        }
                    };

                self.respond(FreeResponse { result }).await
            }
            defs::Command::CREATETHREAD => {
                let req: CreateThreadRequest = self.read().await?;

                let thread_handle = match self.server.create_thread(
                    req.process_handle,
                    req.start_address,
                    req.parameter,
                ) {
                    Ok(handle) => handle,
                    Err(err) => {
                        log::debug!("Could not create thread: {}", err);
                        0
                    }
                };

                self.respond(CreateThreadResponse { thread_handle }).await
            }
            defs::Command::LOADMODULE => {
                let req: LoadModuleRequest = self.read().await?;
                let modulepath = String::from_utf8(req.module_path.into_inner())?;
                log::debug!("Module path: {}", modulepath);

                // TODO: implement

                self.respond(LoadModuleResponse { result: 0 }).await
            }
            defs::Command::SPEEDHACK_SETSPEED => todo!(),
            defs::Command::VIRTUALQUERYEXFULL => {
                let req: VirtualQueryExFullRequest = self.read().await?;
                let flags = VirtualQueryExFullFlags::from_bits(req.flags)
                    .ok_or_else(|| anyhow!("invalid VirtualQueryExFull flags"))?;

                let regions = self.server.virtual_query_full(req.process_handle, flags)?;

                self.respond(VirtualQueryExFullResponse {
                    regions: regions
                        .into_iter()
                        .map(|region| RegionResponse {
                            base: region.base,
                            size: region.size,
                            protection: region.protection.bits(),
                            mem_type: region.mem_type.bits(),
                        })
                        .collect::<Vec<_>>()
                        .into(),
                })
                .await
            }
            defs::Command::GETREGIONINFO => todo!(),
            defs::Command::GETABI => {
                self.respond(GetAbiResponse {
                    abi: self.server.get_abi() as u8,
                })
                .await
            }
            defs::Command::SET_CONNECTION_NAME => {
                let req: SetConnectionNameRequest = self.read().await?;
                let connection_name = String::from_utf8(req.name.into_inner())?;

                log::info!("Updated connection name: {}", connection_name);
                self.connection_name = Cow::Owned(connection_name);

                self.respond(SetConnectionNameResponse::new()).await
            }
            defs::Command::CREATETOOLHELP32SNAPSHOTEX => {
                let req: CreateToolhelp32SnapshotRequest = self.read().await?;
                let flags =
                    Th32Flags::from_bits(req.flags).ok_or_else(|| anyhow!("th32 dwFlags"))?;

                let pid = req.pid;

                if flags.intersects(Th32Flags::TH32CS_SNAPTHREAD) {
                    let threads = self.server.list_threads(pid).unwrap_or_default();

                    self.respond(CreateToolhelp32SnapshotThreadsResponse {
                        thread_ids: threads
                            .into_iter()
                            .map(|te| te.thread_id)
                            .collect::<Vec<_>>()
                            .into(),
                    })
                    .await
                } else if flags.intersects(Th32Flags::TH32CS_SNAPMODULE_ANY) {
                    let modules = self.server.list_modules(pid).unwrap_or_default();

                    let modules = modules
                        .into_iter()
                        .map(|me| ModuleResponse6 {
                            base: me.base,
                            part: me.part,
                            size: me.size,
                            file_offset: me.fileoffset,
                            name: me.name.into(),
                        })
                        .collect::<Vec<_>>();

                    match self.protocol_version {
                        ProtocolVersion::Ver5 => {
                            self.respond(CreateToolhelp32SnapshotModulesResponse5 {
                                modules: modules
                                    .into_iter()
                                    .map(|m| m.into())
                                    .collect::<Vec<ModuleResponse5>>()
                                    .into(),
                            })
                            .await
                        }
                        ProtocolVersion::Ver6 => {
                            self.respond(CreateToolhelp32SnapshotModulesResponse6 {
                                modules: modules.into(),
                            })
                            .await
                        }
                    }
                } else {
                    assert_eq!(flags, Th32Flags::TH32CS_SNAPPROCESS);

                    let snapshot_handle = self.server.create_tlhelp32_snapshot(flags, pid)?;

                    self.respond(CreateToolhelp32SnapshotProcessResponse { snapshot_handle })
                        .await
                }
            }
            defs::Command::CHANGEMEMORYPROTECTION => {
                let req: ChangeMemoryProtectionRequest = self.read().await?;
                let protection = Protection::from_bits(req.protection)
                    .ok_or_else(|| anyhow!("invalid protection"))?;

                let mut result = u32::MAX;

                match self.server.change_memory_protection(
                    req.process_handle,
                    req.address,
                    req.size as usize,
                    protection,
                ) {
                    Ok(_) => {
                        result = 0;
                    }
                    Err(err) => {
                        log::debug!("Could not change memory protection: {}", err)
                    }
                }

                self.respond(ChangeMemoryProtectionResponse {
                    status: result,
                    old_protection: 0, // TODO: implement returning old protection
                })
                .await
            }
            defs::Command::GETOPTIONS => {
                let options = self.server.get_options()?;

                self.respond(GetOptionsResponse {
                    options: options
                        .into_iter()
                        .map(|option| {
                            let opt_value = self
                                .server
                                .get_option_value(option.option_id)
                                .unwrap_or_default();

                            OptionResponse {
                                name: option.name.into(),
                                parent: option.parent.unwrap_or_default().into(),
                                description: option.description.into(),
                                acceptable_values: option
                                    .acceptable_values
                                    .unwrap_or_default()
                                    .into(),
                                opt_value: opt_value.into(),
                                option_type: option.option_type as i32,
                            }
                        })
                        .collect::<Vec<OptionResponse>>()
                        .into(),
                })
                .await
            }
            defs::Command::GETOPTIONVALUE => todo!(),
            defs::Command::SETOPTIONVALUE => todo!(),
            defs::Command::PTRACE_MMAP => todo!(),
            defs::Command::OPENNAMEDPIPE => todo!(),
            defs::Command::PIPEREAD => todo!(),
            defs::Command::PIPEWRITE => todo!(),
            defs::Command::GETCESERVERPATH => todo!(),
            defs::Command::ISANDROID => {
                let is_android = self.server.is_android();
                self.respond(IsAndroidResponse {
                    is_android: if is_android { 1 } else { 0 },
                })
                .await
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
        let req: Process32NextRequest = self.read().await?;

        let pe = {
            let snapshot_shared = self.server.get_tlhelp32_snapshot(req.snapshot_handle)?;
            let mut snapshot = snapshot_shared.lock().unwrap();

            if first {
                snapshot.processes.reset();
            }

            snapshot.processes.next()
        };

        let resp = if let Some(pe) = pe {
            Process32NextResponse {
                item: 1,
                pid: pe.pid,
                name: pe.name.into(),
            }
        } else {
            Process32NextResponse {
                item: 0,
                pid: 0,
                name: "".into(),
            }
        };

        self.respond(resp).await
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
