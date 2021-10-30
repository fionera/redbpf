// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::{mem, ptr};

use crate::bindings::ETH_ALEN;

use crate::{
    bindings::{ethhdr, ETH_P_IP},
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        layer3::{Ipv4, L3Proto},
        FromBytes, Packet,
    },
};

pub struct Ethernet<'a, T: RawBuf> {
    hdr: &'a mut ethhdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Ethernet<'a, T> {
    /// Returns the Source MAC address
    #[inline(always)]
    pub fn source(&self) -> &[u8; 6] {
        &self.hdr.h_source
    }

    /// Returns the Destination MAC address
    #[inline(always)]
    pub fn dest(&self) -> &[u8; 6] {
        &self.hdr.h_dest
    }

    // @TODO Use an enum?
    /// Returns protocol in host byte order
    #[inline(always)]
    pub fn proto(&self) -> u16 {
        u16::from_be(self.hdr.h_proto)
    }
}

impl<'a, T> Ethernet<'a, T>
where
    T: RawBufMut,
{
    /// Sets the source MAC address.
    #[inline(always)]
    pub fn set_source(&mut self, val: &[u8; 6]) {
        // Invariants that must be upheld for `ptr::copy_nonoverlapping`:
        //
        // - src must be valid for reads of count * size_of::<T>() bytes.
        // - dst must be valid for writes of count * size_of::<T>() bytes.
        // - Both src and dst must be properly aligned.
        // - The region of memory beginning at src with a size of count *
        //   size_of::<T>() bytes must not overlap with the region of memory
        //   beginning at dst with the same size.
        //
        // Checks performed:
        //
        // - addresses + size of field do not overlap
        unsafe {
            // @SAFETY no alignment is checked because [u8; 6] has align of 1
            let dst_ptr = (&mut self.hdr.h_source) as *mut _ as *mut _;
            let src_ptr = val.as_ptr();

            // ensure no overlap
            if dst_ptr as usize >= src_ptr as usize
                && dst_ptr as usize <= (src_ptr as usize + ETH_ALEN as usize)
            {
                panic!("Source and Destination addresses overlap in Ethernet::set_source");
            }

            ptr::copy_nonoverlapping(src_ptr, dst_ptr, ETH_ALEN as usize);
        }
    }

    /// Sets the Destination MAC address
    #[inline(always)]
    pub fn set_dest(&mut self, val: &[u8; 6]) {
        // Invariants that must be upheld for `ptr::copy_nonoverlapping`:
        //
        // - src must be valid for reads of count * size_of::<T>() bytes.
        // - dst must be valid for writes of count * size_of::<T>() bytes.
        // - Both src and dst must be properly aligned.
        // - The region of memory beginning at src with a size of count *
        //   size_of::<T>() bytes must not overlap with the region of memory
        //   beginning at dst with the same size.
        //
        // Checks performed:
        //
        // - addresses + size of field do not overlap
        unsafe {
            // @SAFETY no alignment is checked because [u8; 6] has align of 1
            let dst_ptr = (&mut self.hdr.h_dest) as *mut _ as *mut _;
            let src_ptr = val.as_ptr();

            // ensure no overlap
            if dst_ptr as usize >= src_ptr as usize
                && dst_ptr as usize <= (src_ptr as usize + ETH_ALEN as usize)
            {
                panic!("Source and Destination addresses overlap in Ethernet::set_dest");
            }

            ptr::copy_nonoverlapping(src_ptr, dst_ptr, ETH_ALEN as usize);
        }
    }

    /// Sets the protocol.
    ///
    /// **NOTE:** `val` will be converted from host-byte-order to
    /// network-byte-order (BE) as part of the write process.
    #[inline(always)]
    pub fn set_proto(&mut self, val: u16) {
        self.hdr.h_proto = u16::to_be(val);
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Ethernet<'a, T> {
    type Encapsulated = L3Proto<'a, T>;

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
        match self.proto() {
            p if p == ETH_P_IP as u16 => Ok(L3Proto::Ipv4(self.parse_as::<Ipv4<T>>()?)),
            p => Err(Error::UnimplementedProtocol(p as u32)),
        }
    }
}

unsafe impl<'a, T> FromBytes<'a, T> for Ethernet<'a, T>
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
            if let Some(eth) = buf.ptr_at::<ethhdr>(buf.nh_offset) {
                buf.nh_offset += mem::size_of::<ethhdr>();
                if let Some(eth) = (eth as *mut ethhdr).as_mut() {
                    return Ok(Ethernet { buf, hdr: eth });
                }
                return Err(Error::NullPtr);
            }
            Err(Error::OutOfBounds)
        }
    }
}
