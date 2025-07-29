use std::marker::PhantomData;

use crate::server::{CeAddress, CeHandle, CeProcessId};

use super::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Default)]
pub struct BytesVariant<V>(Vec<u8>, PhantomData<V>);

impl<V> BytesVariant<V> {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<V> From<Vec<u8>> for BytesVariant<V> {
    fn from(value: Vec<u8>) -> Self {
        Self(value, PhantomData)
    }
}

impl<V> From<String> for BytesVariant<V> {
    fn from(value: String) -> Self {
        value.into_bytes().into()
    }
}

impl<V> From<&str> for BytesVariant<V> {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

impl<V: VariantLength> Serialize for BytesVariant<V> {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        if self.0.len() > V::MAX {
            return Err(anyhow::anyhow!("bytes' length does not fit in type"));
        }

        V::from_usize(self.0.len()).serialize(serializer)?;
        (self.0.as_slice()).serialize(serializer)?;
        Ok(())
    }
}

impl<V: VariantLength> Deserialize for BytesVariant<V> {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        let length = V::deserialize(deserializer).await?;
        let mut buf = vec![0; length.into_usize()];
        deserializer.read_bytes(&mut buf).await?;
        Ok(buf.into())
    }
}

#[derive(Debug)]
pub struct VecVariant<T, V>(Vec<T>, PhantomData<V>);

impl<T, V> From<Vec<T>> for VecVariant<T, V> {
    fn from(value: Vec<T>) -> Self {
        Self(value, PhantomData)
    }
}

impl<T, V> VecVariant<T, V> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, V> Serialize for VecVariant<T, V>
where
    T: Serialize,
    V: VariantLength,
{
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        if self.0.len() > V::MAX {
            return Err(anyhow::anyhow!("bytes' length does not fit in type"));
        }

        V::from_usize(self.0.len()).serialize(serializer)?;

        for item in &self.0 {
            item.serialize(serializer)?;
        }

        Ok(())
    }
}

impl<T, V> Deserialize for VecVariant<T, V>
where
    T: Deserialize,
    V: VariantLength,
{
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        let length = V::deserialize(deserializer).await?.into_usize();
        let mut buf = Vec::with_capacity(length);

        for _ in 0..length {
            buf.push(T::deserialize(deserializer).await?);
        }

        Ok(buf.into())
    }
}

pub trait VariantLength: Serialize + Deserialize {
    const MAX: usize;

    fn from_usize(v: usize) -> Self;

    fn into_usize(&self) -> usize;
}

macro_rules! impl_variant_length {
    ($t:ty) => {
        impl VariantLength for $t {
            const MAX: usize = <$t>::MAX as usize;

            fn from_usize(v: usize) -> Self {
                v as Self
            }

            fn into_usize(&self) -> usize {
                *self as usize
            }
        }
    };
}

impl_variant_length!(u8);
impl_variant_length!(u16);
impl_variant_length!(u32);

pub type Bytes8 = BytesVariant<u8>;
pub type Bytes16 = BytesVariant<u16>;
pub type Bytes32 = BytesVariant<u32>;

pub type Vec8<T> = VecVariant<T, u8>;
pub type Vec16<T> = VecVariant<T, u16>;
pub type Vec32<T> = VecVariant<T, u32>;

#[derive(Debug)]
pub struct TerminatedList<T>(Vec<T>);

impl<T> From<Vec<T>> for TerminatedList<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T> Serialize for TerminatedList<T>
where
    T: Serialize + Default,
{
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        for item in &self.0 {
            (1 as u32).serialize(serializer)?;
            item.serialize(serializer)?;
        }

        (0 as u32).serialize(serializer)?;
        T::default().serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetVersionResponse {
    pub version_number: i32,
    pub version_string: Bytes8,
}

impl GetVersionResponse {
    pub fn new(version_number: i32, version_string: String) -> Self {
        Self {
            version_number,
            version_string: version_string.into(),
        }
    }
}

impl Serialize for GetVersionResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.version_number.serialize(serializer)?;
        self.version_string.serialize(serializer)?;
        Ok(())
    }
}

impl Deserialize for GetVersionResponse {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            version_number: <i32 as Deserialize>::deserialize(deserializer).await?,
            version_string: <Bytes8 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct EmptyResponse;

impl EmptyResponse {
    pub fn new() -> Self {
        Self
    }
}

impl Serialize for EmptyResponse {
    fn serialize<S: Serializer>(&self, _serializer: &mut S) -> anyhow::Result<()> {
        Ok(())
    }
}

pub type TerminateServerResponse = EmptyResponse;

#[derive(Debug)]
pub struct OpenProcessRequest {
    pub process_id: CeProcessId,
}

impl Deserialize for OpenProcessRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_id: <CeProcessId as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct OpenProcessResponse {
    pub process_handle: CeHandle,
}

impl Serialize for OpenProcessResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.process_handle.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CloseHandleRequest {
    pub handle: CeHandle,
}

impl Deserialize for CloseHandleRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct CloseHandleResponse {
    pub status: u32,
}

impl Serialize for CloseHandleResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.status.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtualQueryExRequest {
    pub process_handle: CeHandle,
    pub base: CeAddress,
}

impl Deserialize for VirtualQueryExRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            base: <CeAddress as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct VirtualQueryExResponse {
    pub status: u8,
    pub protection: u32,
    pub mem_type: u32,
    pub base: u64,
    pub size: u64,
}

impl Serialize for VirtualQueryExResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.status.serialize(serializer)?;
        self.protection.serialize(serializer)?;
        self.mem_type.serialize(serializer)?;
        self.base.serialize(serializer)?;
        self.size.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadProcessMemoryRequest {
    pub process_handle: CeHandle,
    pub base: u64,
    pub size: u32,
    pub compress: u8,
}

impl Deserialize for ReadProcessMemoryRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            base: <u64 as Deserialize>::deserialize(deserializer).await?,
            size: <u32 as Deserialize>::deserialize(deserializer).await?,
            compress: <u8 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct ReadProcessMemoryResponse {
    pub data: Bytes32,
}

impl Serialize for ReadProcessMemoryResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.data.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteProcessMemoryRequest {
    pub process_handle: CeHandle,
    pub base: u64,
    pub data: Bytes32,
}

impl Deserialize for WriteProcessMemoryRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            base: <u64 as Deserialize>::deserialize(deserializer).await?,
            data: <Bytes32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct WriteProcessMemoryResponse {
    pub status: u32,
}

impl Serialize for WriteProcessMemoryResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.status.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StartDebugRequest {
    pub process_handle: CeHandle,
}

impl Deserialize for StartDebugRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct StartDebugResponse {
    pub status: u32,
}

impl Serialize for StartDebugResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.status.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetArchitectureRequest {
    pub process_handle: CeHandle,
}

impl Deserialize for GetArchitectureRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct GetArchitectureResponse {
    pub architecture: u8,
}

impl Serialize for GetArchitectureResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.architecture.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetAbiResponse {
    pub abi: u8,
}

impl Serialize for GetAbiResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.abi.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct WaitForDebugEventRequest {
    pub process_handle: CeHandle,
    pub timeout: u32,
}

impl Deserialize for WaitForDebugEventRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            timeout: <u32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

pub type WaitForDebugEventResponse = EmptyResponse;

#[derive(Debug)]
pub struct SetConnectionNameRequest {
    pub name: Bytes32,
}

impl Deserialize for SetConnectionNameRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            name: <Bytes32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

pub type SetConnectionNameResponse = EmptyResponse;

#[derive(Debug)]
pub struct IsAndroidResponse {
    pub is_android: u8,
}

impl Serialize for IsAndroidResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.is_android.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetOptionsResponse {
    pub options: Vec16<OptionResponse>,
}

#[derive(Debug)]
pub struct OptionResponse {
    pub name: Bytes16,
    pub parent: Bytes16,
    pub description: Bytes16,
    pub acceptable_values: Bytes16,
    pub opt_value: Bytes16,
    pub option_type: i32,
}

impl Serialize for GetOptionsResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.options.serialize(serializer)?;
        Ok(())
    }
}

impl Serialize for OptionResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.name.serialize(serializer)?;
        self.parent.serialize(serializer)?;
        self.description.serialize(serializer)?;
        self.acceptable_values.serialize(serializer)?;
        self.opt_value.serialize(serializer)?;
        self.option_type.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ChangeMemoryProtectionRequest {
    pub process_handle: CeHandle,
    pub address: CeAddress,
    pub size: u64,
    pub protection: u32,
}

impl Deserialize for ChangeMemoryProtectionRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            address: <CeAddress as Deserialize>::deserialize(deserializer).await?,
            size: <u64 as Deserialize>::deserialize(deserializer).await?,
            protection: <u32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct ChangeMemoryProtectionResponse {
    pub status: u32,
    pub old_protection: u32,
}

impl Serialize for ChangeMemoryProtectionResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.status.serialize(serializer)?;
        self.old_protection.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AllocRequest {
    pub process_handle: CeHandle,
    pub address: CeAddress,
    pub size: u32,
    pub protection: u32,
}

impl Deserialize for AllocRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            address: <CeAddress as Deserialize>::deserialize(deserializer).await?,
            size: <u32 as Deserialize>::deserialize(deserializer).await?,
            protection: <u32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct AllocResponse {
    pub address: u64,
}

impl Serialize for AllocResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.address.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct FreeRequest {
    pub process_handle: CeHandle,
    pub address: CeAddress,
    pub size: u32,
}

impl Deserialize for FreeRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            address: <CeAddress as Deserialize>::deserialize(deserializer).await?,
            size: <u32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct FreeResponse {
    pub result: u32,
}

impl Serialize for FreeResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.result.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateThreadRequest {
    pub process_handle: CeHandle,
    pub start_address: CeAddress,
    pub parameter: u64,
}

impl Deserialize for CreateThreadRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            start_address: <CeAddress as Deserialize>::deserialize(deserializer).await?,
            parameter: <u64 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct CreateThreadResponse {
    pub thread_handle: CeHandle,
}

impl Serialize for CreateThreadResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.thread_handle.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetSymbolListFromFileRequest5 {
    pub symbolpath: Bytes32,
}

impl Deserialize for GetSymbolListFromFileRequest5 {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            symbolpath: <Bytes32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct GetSymbolListFromFileRequest6 {
    pub file_offset: u32,
    pub symbolpath: Bytes32,
}

impl Deserialize for GetSymbolListFromFileRequest6 {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            file_offset: <u32 as Deserialize>::deserialize(deserializer).await?,
            symbolpath: <Bytes32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

impl From<GetSymbolListFromFileRequest5> for GetSymbolListFromFileRequest6 {
    fn from(value: GetSymbolListFromFileRequest5) -> Self {
        Self {
            file_offset: 0,
            symbolpath: value.symbolpath,
        }
    }
}

#[derive(Debug)]
pub struct GetSymbolListFromFileResponse {
    pub result: u64,
}

impl Serialize for GetSymbolListFromFileResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.result.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Process32NextRequest {
    pub snapshot_handle: CeHandle,
}

impl Deserialize for Process32NextRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            snapshot_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct Process32NextResponse {
    pub item: u32,
    pub pid: u32,
    pub name: Bytes32,
}

impl Serialize for Process32NextResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.item.serialize(serializer)?;
        self.pid.serialize(serializer)?;
        self.name.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateToolhelp32SnapshotRequest {
    pub flags: u32,
    pub pid: u32,
}

impl Deserialize for CreateToolhelp32SnapshotRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            flags: <u32 as Deserialize>::deserialize(deserializer).await?,
            pid: <u32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct CreateToolhelp32SnapshotThreadsResponse {
    pub thread_ids: Vec32<u32>,
}

impl Serialize for CreateToolhelp32SnapshotThreadsResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.thread_ids.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateToolhelp32SnapshotProcessResponse {
    pub snapshot_handle: CeHandle,
}

impl Serialize for CreateToolhelp32SnapshotProcessResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.snapshot_handle.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateToolhelp32SnapshotModulesBaseResponse<T> {
    pub modules: TerminatedList<T>,
}

pub type CreateToolhelp32SnapshotModulesResponse5 =
    CreateToolhelp32SnapshotModulesBaseResponse<ModuleResponse5>;
pub type CreateToolhelp32SnapshotModulesResponse6 =
    CreateToolhelp32SnapshotModulesBaseResponse<ModuleResponse6>;

impl<T> Serialize for CreateToolhelp32SnapshotModulesBaseResponse<T>
where
    T: Serialize + Default,
{
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.modules.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ModuleResponse5 {
    pub base: CeAddress,
    pub part: u32,
    pub size: u32,
    pub name: Bytes32,
}

impl Serialize for ModuleResponse5 {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.base.serialize(serializer)?;
        self.part.serialize(serializer)?;
        self.size.serialize(serializer)?;
        self.name.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ModuleResponse6 {
    pub base: CeAddress,
    pub part: u32,
    pub size: u32,
    pub file_offset: u32,
    pub name: Bytes32,
}

impl Serialize for ModuleResponse6 {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.base.serialize(serializer)?;
        self.part.serialize(serializer)?;
        self.size.serialize(serializer)?;
        self.file_offset.serialize(serializer)?;
        self.name.serialize(serializer)?;
        Ok(())
    }
}

impl From<ModuleResponse6> for ModuleResponse5 {
    fn from(value: ModuleResponse6) -> Self {
        Self {
            base: value.base,
            part: value.part,
            size: value.size,
            name: value.name,
        }
    }
}

#[derive(Debug)]
pub struct VirtualQueryExFullRequest {
    pub process_handle: CeHandle,
    pub flags: u8,
}

impl Deserialize for VirtualQueryExFullRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            flags: <u8 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct VirtualQueryExFullResponse {
    pub regions: Vec32<RegionResponse>,
}

impl Serialize for VirtualQueryExFullResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.regions.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RegionResponse {
    pub base: CeAddress,
    pub size: u64,
    pub protection: u32,
    pub mem_type: u32,
}

impl Serialize for RegionResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.base.serialize(serializer)?;
        self.size.serialize(serializer)?;
        self.protection.serialize(serializer)?;
        self.mem_type.serialize(serializer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct LoadModuleRequest {
    pub process_handle: CeHandle,
    pub module_path: Bytes32,
}

impl Deserialize for LoadModuleRequest {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
        Ok(Self {
            process_handle: <CeHandle as Deserialize>::deserialize(deserializer).await?,
            module_path: <Bytes32 as Deserialize>::deserialize(deserializer).await?,
        })
    }
}

#[derive(Debug)]
pub struct LoadModuleResponse {
    pub result: u64,
}

impl Serialize for LoadModuleResponse {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
        self.result.serialize(serializer)?;
        Ok(())
    }
}
