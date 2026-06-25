//! Deterministic binary encoding.
//!
//! Consensus depends on every node hashing byte-identical bytes, so the wire
//! format used for signing, hashing and on-disk storage is written by hand here
//! rather than delegated to a general-purpose serialisation crate: fixed-width
//! little-endian integers, length-prefixed blobs, no field names, no options
//! beyond an explicit presence byte.
//!
//! JSON (via `serde`) is used only for human-facing surfaces: HTTP payloads,
//! genesis files and keystores.

use crate::bytes::{Address, Bytes, Hash};
use crate::error::{Error, Result};

/// Growable buffer with primitive writers.
#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Raw bytes, no length prefix (for fixed-size fields).
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Length-prefixed bytes.
    pub fn var(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.raw(v)
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.var(v.as_bytes())
    }

    pub fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            Some(x) => {
                self.u8(1);
                self.u64(x)
            }
            None => self.u8(0),
        }
    }

    pub fn write<T: Encode>(&mut self, v: &T) -> &mut Self {
        v.encode(self);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Cursor over an encoded buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::UnexpectedEof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(Error::InvalidTag { kind: "bool", tag }),
        }
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn var(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub fn str(&mut self) -> Result<String> {
        let bytes = self.var()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Other("invalid utf8".into()))
    }

    pub fn opt_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            tag => Err(Error::InvalidTag {
                kind: "Option<u64>",
                tag,
            }),
        }
    }

    pub fn read<T: Decode>(&mut self) -> Result<T> {
        T::decode(self)
    }

    /// Fail if any bytes are left over, catching truncated or padded records.
    pub fn finish(self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::TrailingBytes(self.remaining()));
        }
        Ok(())
    }
}

pub trait Encode {
    fn encode(&self, w: &mut Writer);

    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }
}

pub trait Decode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self>;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let out = Self::decode(&mut r)?;
        r.finish()?;
        Ok(out)
    }
}

impl Encode for Address {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.as_bytes());
    }
}

impl Decode for Address {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Address(r.array::<32>()?))
    }
}

impl Encode for Hash {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.as_bytes());
    }
}

impl Decode for Hash {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Hash(r.array::<32>()?))
    }
}

impl<const N: usize> Encode for Bytes<N> {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.as_slice());
    }
}

impl<const N: usize> Decode for Bytes<N> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Bytes::new(r.array::<N>()?))
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, w: &mut Writer) {
        w.u32(self.len() as u32);
        for item in self {
            item.encode(w);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let len = r.u32()? as usize;
        // Length is attacker-controlled; grow on demand instead of reserving.
        let mut out = Vec::new();
        for _ in 0..len {
            out.push(T::decode(r)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip() {
        let mut w = Writer::new();
        w.u8(7)
            .bool(true)
            .u32(0xdead_beef)
            .u64(u64::MAX)
            .str("sikka")
            .opt_u64(Some(9))
            .opt_u64(None);
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert!(r.bool().unwrap());
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.str().unwrap(), "sikka");
        assert_eq!(r.opt_u64().unwrap(), Some(9));
        assert_eq!(r.opt_u64().unwrap(), None);
        r.finish().unwrap();
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut w = Writer::new();
        w.u64(1);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes[..4]);
        assert_eq!(r.u64().unwrap_err(), Error::UnexpectedEof);
    }

    #[test]
    fn trailing_input_is_rejected() {
        let mut w = Writer::new();
        w.u64(1).u8(0);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        r.u64().unwrap();
        assert_eq!(r.finish().unwrap_err(), Error::TrailingBytes(1));
    }

    #[test]
    fn address_and_vec_roundtrip() {
        let addrs = vec![Address([1u8; 32]), Address([2u8; 32])];
        let bytes = addrs.to_bytes();
        assert_eq!(Vec::<Address>::from_bytes(&bytes).unwrap(), addrs);
    }

    #[test]
    fn declared_length_beyond_input_errors() {
        // A hostile record claiming a huge vector must fail, not allocate.
        let mut w = Writer::new();
        w.u32(u32::MAX);
        let bytes = w.finish();
        assert!(Vec::<Address>::from_bytes(&bytes).is_err());
    }
}
