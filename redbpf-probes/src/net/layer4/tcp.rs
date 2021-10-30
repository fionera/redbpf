// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::tcphdr,
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        FromBytes, Packet,
    },
};

pub struct Tcp<'a, T: RawBuf> {
    hdr: &'a mut tcphdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Tcp<'a, T> {
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

    /// Returns the sequence number in host-byte-order
    #[inline(always)]
    pub fn seq(&self) -> u32 {
        u32::from_be(self.hdr.seq)
    }

    /// Returns the ACK (acknowledgement) number in host-byte-order
    #[inline(always)]
    pub fn ack_seq(&self) -> u32 {
        u32::from_be(self.hdr.ack_seq)
    }

    /// Returns the "data offset" (i.e. header length) in bytes
    #[inline]
    pub fn doff(&self) -> u8 {
        self.hdr._bitfield_1.get(4, 4) as u8
    }

    /// Returns `true` if any of the `RES1` ("reserved") bits are set in the TCP
    /// flags
    #[inline]
    pub fn res1(&self) -> bool {
        self.hdr._bitfield_1.get(4, 4) as u16 & 0x000F != 0
    }

    /// Returns `true` if any of the `RES2` ("reserved" / `ECE` and `CWR`) bits
    /// are set in the TCP flags
    #[inline]
    pub fn res2(&self) -> bool {
        self.hdr._bitfield_1.get(14, 2) as u16 & 0x6000 != 0
    }

    /// Returns `true` if the `FIN` ("finish") bit is set in the TCP flags
    #[inline]
    pub fn fin(&self) -> bool {
        self.hdr._bitfield_1.get_bit(8)
    }

    /// Returns `true` if the `SYN` ("synchronize") bit is set in the TCP flags
    #[inline]
    pub fn syn(&self) -> bool {
        self.hdr._bitfield_1.get_bit(9)
    }

    /// Returns `true` if the `RST` ("reset") bit is set in the TCP flags
    #[inline]
    pub fn rst(&self) -> bool {
        self.hdr._bitfield_1.get_bit(10)
    }

    /// Returns `true` if the `PSH` ("push") bit is set in the TCP flags
    #[inline]
    pub fn psh(&self) -> bool {
        self.hdr._bitfield_1.get_bit(11)
    }

    /// Returns `true` if the `ACK` ("acknowledge") bit is set in the TCP flags
    #[inline]
    pub fn ack(&self) -> bool {
        self.hdr._bitfield_1.get_bit(12)
    }

    /// Returns `true` if the `URG` ("urgent") bit is set in the TCP flags
    #[inline]
    pub fn urg(&self) -> bool {
        self.hdr._bitfield_1.get_bit(13)
    }

    /// Returns `true` if the `ECE` ("ECN echo") bit is set in the TCP flags
    #[inline]
    pub fn ece(&self) -> bool {
        self.hdr._bitfield_1.get_bit(14)
    }

    /// Returns `true` if the `CWR` ("congestion window reduced") bit is set in
    /// the TCP flags
    #[inline]
    pub fn cwr(&self) -> bool {
        self.hdr._bitfield_1.get_bit(15)
    }
}

impl<'a, T> Tcp<'a, T>
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

    /// Sets the sequence number
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_seq(&mut self, val: u32) {
        self.hdr.seq = u32::to_be(val);
    }

    /// Sets the ACK (acknowledgement) number
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    #[inline(always)]
    pub fn set_ack_seq(&mut self, val: u32) {
        self.hdr.ack_seq = u32::from_be(val);
    }

    /// Sets the "data offset" (i.e. header length) in bytes
    #[inline]
    pub fn set_doff(&mut self, val: u8) {
        self.hdr._bitfield_1.set(4, 4, val as u64);
    }

    /// Sets any of the `RES1` ("reserved") bits in the TCP flags
    #[inline]
    pub fn set_res1(&mut self, val: u8) {
        self.hdr._bitfield_1.set(0, 4, val as u64);
    }

    /// Sets any of the `RES2` ("reserved" / `ECE` and `CWR`) bits in the TCP
    /// flags
    #[inline]
    pub fn set_res2(&mut self, val: u8) {
        self.hdr._bitfield_1.set(14, 2, val as u64);
    }

    /// Sets the `FIN` ("finish") bit in the TCP flags
    #[inline]
    pub fn set_fin(&mut self) {
        self.hdr._bitfield_1.set_bit(8, true);
    }

    /// Sets the `SYN` ("synchronize") bit in the TCP flags
    #[inline]
    pub fn set_syn(&mut self) {
        self.hdr._bitfield_1.set_bit(9, true);
    }

    /// Sets the `RST` ("reset") bit in the TCP flags
    #[inline]
    pub fn set_rst(&mut self) {
        self.hdr._bitfield_1.set_bit(10, true);
    }

    /// Sets the `PSH` ("push") bit in the TCP flags
    #[inline]
    pub fn set_psh(&mut self) {
        self.hdr._bitfield_1.set_bit(11, true);
    }

    /// Sets the `ACK` ("acknowledge") bit in the TCP flags
    #[inline]
    pub fn set_ack(&mut self) {
        self.hdr._bitfield_1.set_bit(12, true);
    }

    /// Sets the `URG` ("urgent") bit in the TCP flags
    #[inline]
    pub fn set_urg(&mut self) {
        self.hdr._bitfield_1.set_bit(13, true);
    }

    /// Sets the `ECE` ("ECN echo") bit in the TCP flags
    #[inline]
    pub fn set_ece(&mut self) {
        self.hdr._bitfield_1.set_bit(14, true);
    }

    /// Sets the `CWR` ("congestion window reduced") bit in the TCP flags
    #[inline]
    pub fn set_cwr(&mut self) {
        self.hdr._bitfield_1.set_bit(15, true);
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Tcp<'a, T> {
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

unsafe impl<'a, T> FromBytes<'a, T> for Tcp<'a, T>
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
            if let Some(tcp) = buf.ptr_at::<tcphdr>(buf.nh_offset) {
                buf.nh_offset += mem::size_of::<tcphdr>();
                if let Some(tcp) = (tcp as *mut tcphdr).as_mut() {
                    return Ok(Tcp { buf, hdr: tcp });
                }
                return Err(Error::NullPtr);
            }
            Err(Error::OutOfBounds)
        }
    }
}
