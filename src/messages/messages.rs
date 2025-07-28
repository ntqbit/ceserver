use std::io::{self, Cursor};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{ser::SerializeTupleStruct, Deserialize, Serialize};

use crate::server::{CeAddress, CeHandle, CeProcessId};

pub struct Reader {
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

pub struct Writer {
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
        io::Write::write_all(&mut self.buf, bytes).unwrap();
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

#[derive(Debug)]
pub struct BytesVariant<const N: usize>(Vec<u8>);

impl<const N: usize> From<String> for BytesVariant<N> {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}

impl<const N: usize> From<&str> for BytesVariant<N> {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

macro_rules! impl_bytes_variant {
    ($n:literal, $t:ty) => {
        impl Serialize for BytesVariant<$n> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if self.0.len() > <$t>::MAX as usize {
                    return Err(serde::ser::Error::custom(
                        "bytes' length does not fit in type",
                    ));
                }

                let mut s = serializer.serialize_tuple_struct("", 2)?;
                s.serialize_field(&(self.0.len() as $t))?;
                s.serialize_field(&self.0)?;
                s.end()
            }
        }
    };
}

impl_bytes_variant!(8, u8);
impl_bytes_variant!(16, u16);
impl_bytes_variant!(32, u32);

pub type Bytes8 = BytesVariant<8>;
pub type Bytes16 = BytesVariant<16>;
pub type Bytes32 = BytesVariant<32>;

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct EmptyResponse;

impl EmptyResponse {
    pub fn new() -> Self {
        Self
    }
}

pub type TerminateServerResponse = EmptyResponse;

#[derive(Debug, Deserialize)]
pub struct OpenProcessRequest {
    pub process_id: CeProcessId,
}

#[derive(Debug, Serialize)]
pub struct OpenProcessResponse {
    pub process_handle: CeHandle,
}
