struct CeSerializer {
    buf: Vec<u8>,
}

impl CeSerializer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Serializer for CeSerializer {
    fn write_u8(&mut self, v: u8) {
        self.write_bytes(&[v]);
    }

    fn write_u16(&mut self, v: u16) {
        self.write_bytes(&v.to_le_bytes());
    }

    fn write_u32(&mut self, v: u32) {
        self.write_bytes(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.write_bytes(&v.to_le_bytes());
    }

    fn write_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

pub trait Serializer {
    fn write_u8(&mut self, v: u8);

    fn write_u16(&mut self, v: u16);

    fn write_u32(&mut self, v: u32);

    fn write_u64(&mut self, v: u64);

    fn write_bytes(&mut self, v: &[u8]);
}

pub trait Serialize {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()>;
}

pub fn serialize<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut serializer = CeSerializer::new();
    value.serialize(&mut serializer)?;
    Ok(serializer.into_inner())
}

macro_rules! impl_serialize_primitive {
    ($t:ty, $func:ident) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
                serializer.$func(*self);
                Ok(())
            }
        }
    };
}

macro_rules! impl_serialize_forward {
    ($t:ty, $as:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, serializer: &mut S) -> anyhow::Result<()> {
                (*self as $as).serialize(serializer)
            }
        }
    };
}

impl_serialize_primitive!(u8, write_u8);
impl_serialize_primitive!(u16, write_u16);
impl_serialize_primitive!(u32, write_u32);
impl_serialize_primitive!(u64, write_u64);
impl_serialize_primitive!(&[u8], write_bytes);

impl_serialize_forward!(i32, u32);
