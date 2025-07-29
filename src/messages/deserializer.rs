use tokio::io::{AsyncRead, AsyncReadExt};

pub type CeDeserializeError = anyhow::Error;

struct CeDeserializer<R> {
    reader: R,
}

impl<R> CeDeserializer<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R> CeDeserializer<R>
where
    R: AsyncRead + Unpin,
{
    async fn read_raw(&mut self, buf: &mut [u8]) -> Result<(), CeDeserializeError> {
        self.reader.read_exact(buf).await?;
        Ok(())
    }
}

impl<R> Deserializer for CeDeserializer<R>
where
    R: AsyncRead + Unpin,
{
    type Error = CeDeserializeError;

    async fn read_u8(&mut self) -> Result<u8, Self::Error> {
        let mut v = [0];
        self.read_raw(&mut v).await?;
        Ok(v[0])
    }

    async fn read_u16(&mut self) -> Result<u16, Self::Error> {
        let mut v = [0; 2];
        self.read_raw(&mut v).await?;
        Ok(u16::from_le_bytes(v))
    }

    async fn read_u32(&mut self) -> Result<u32, Self::Error> {
        let mut v = [0; 4];
        self.read_raw(&mut v).await?;
        Ok(u32::from_le_bytes(v))
    }

    async fn read_u64(&mut self) -> Result<u64, Self::Error> {
        let mut v = [0; 8];
        self.read_raw(&mut v).await?;
        Ok(u64::from_le_bytes(v))
    }

    async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_raw(buf).await
    }
}

pub trait Deserializer {
    type Error;

    async fn read_u8(&mut self) -> Result<u8, Self::Error>;

    async fn read_u16(&mut self) -> Result<u16, Self::Error>;

    async fn read_u32(&mut self) -> Result<u32, Self::Error>;

    async fn read_u64(&mut self) -> Result<u64, Self::Error>;

    async fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait Deserialize: Sized {
    async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error>;
}

pub async fn deserialize<T: Deserialize, R: AsyncRead + Unpin>(
    reader: R,
) -> Result<T, CeDeserializeError> {
    let mut deserializer = CeDeserializer::new(reader);
    T::deserialize(&mut deserializer).await
}

macro_rules! impl_deserialize_primitive {
    ($t:ty, $func:ident) => {
        impl Deserialize for $t {
            async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
                deserializer.$func().await
            }
        }
    };
}

macro_rules! impl_deserialize_forward {
    ($t:ty, $as:ty) => {
        impl Deserialize for $t {
            async fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<Self, D::Error> {
                Ok(<$as as Deserialize>::deserialize(deserializer).await? as Self)
            }
        }
    };
}

impl_deserialize_primitive!(u8, read_u8);
impl_deserialize_primitive!(u16, read_u16);
impl_deserialize_primitive!(u32, read_u32);
impl_deserialize_primitive!(u64, read_u64);

impl_deserialize_forward!(i32, u32);
