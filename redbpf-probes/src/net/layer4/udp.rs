// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::udphdr,
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        FromBytes, Packet,
    },
};

pub struct Udp<'a, T: RawBuf> {
    hdr: &'a mut udphdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Udp<'a, T> {
    /// Returns the source port in host-byte-order
    #[inline(always)]
    pub fn source(&self) -> u16 {
        u16::from_be(self.hdr.source)
    }

    /// Returns the destination port in host-byte-order
    #[inline(always)]
    pub fn dest(&self) -> u16 {
        u16::from_be(self.hdr.dest)
    }

    /// Returns the length (UDP header + UDP payload) in host-byte-order
    #[inline(always)]
    pub fn len(&self) -> u16 {
        u16::from_be(self.hdr.len)
    }

    /// Returns the checksum in host-byte-order
    #[inline(always)]
    pub fn check(&self) -> u16 {
        u16::from_be(self.hdr.check)
    }
}

impl<'a, T> Udp<'a, T>
where
    T: RawBufMut,
{
    /// Sets the source port
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_source(&mut self, val: u16) {
        self.hdr.source = u16::to_be(val);
    }

    /// Sets the destination port
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_dest(&mut self, val: u16) {
        self.hdr.dest = u16::to_be(val);
    }

    /// Sets the length (UDP header + UDP payload)
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_len(&mut self, val: u16) {
        self.hdr.len = u16::to_be(val);
    }

    /// Sets the checksum
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_check(&mut self, val: u16) {
        self.hdr.check = u16::to_be(val);
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Udp<'a, T> {
    type Encapsulated = NetBuf<'a, T>;

    #[inline(always)]
    fn buf(self) -> NetBuf<'a, T> {
        self.buf
    }

    #[inline(always)]
    fn buf_ref(&self) -> &NetBuf<'a, T> {
        &self.buf
    }

    #[inline(always)]
    fn offset(&self) -> usize {
        self.buf.offset()
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.buf.end() - (self.buf.start() + self.offset())
    }

    #[inline(always)]
    fn body(&self) -> &[u8] {
        self.buf.slice_at(self.offset(), self.buf.end() - (self.buf.start() + self.offset()))
    }

    #[inline(always)]
    fn parse(self) -> Result<Self::Encapsulated> {
        Ok(self.buf)
    }
}

unsafe impl<'a, T> FromBytes<'a, T> for Udp<'a, T>
where
    T: RawBuf,
{
    #[inline(always)]
    fn from_bytes(mut buf: NetBuf<'a, T>) -> Result<Self> {
        // @SAFETY
        //
        // The invariants must be be upheld for the type requested with
        // `RawBuf::ptr_at`:
        //
        // - Alignment of 1 ( or #[repr(C, packed)])
        //
        // Checks performed:
        //
        // - `RawBuf::ptr_at` does bounds check
        // - Using `*mut::as_mut` does null check
        unsafe {
            if let Some(tcp) = buf.ptr_at::<udphdr>(buf.nh_offset) {
                buf.nh_offset += mem::size_of::<udphdr>();
                if let Some(tcp) = (tcp as *mut udphdr).as_mut() {
                    return Ok(Udp { buf, hdr: tcp });
                }
                return Err(Error::NullPtr);
            }
            Err(Error::OutOfBounds)
        }
    }
}
