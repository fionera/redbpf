// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::{marker::PhantomData, mem, ptr, slice};

use crate::net::{
    error::{Error, Result},
    layer2::L2Proto,
    FromBe, FromBytes, Packet,
};

/// Represents a raw Buffer ("raw" meaning it works with, and gives out raw
/// pointers) such as that pointed to by [`XdpContext`]. This trait is meant to
/// be a low level building block for higher level abstractions.
///
/// The only required methods are `RawBuf::start` and `RawBuf::end` which return
/// an address to the start and and end of the buffer.
///
/// If one does not have an end address, you can re-implement `RawBuf::len` and
/// simply add it to `RawBuf::start`
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait RawBuf {
    /// Returns the start address of the buffer
    fn start(&self) -> usize;

    /// Returns the end address of the buffer
    fn end(&self) -> usize;

    /// Returns the buffer byte length.
    #[inline]
    fn len(&self) -> usize {
        self.end() - self.start()
    }

    /// Returns a raw pointer to the address of `self.start() + offset` ensuring
    /// the remaining space is enough to point to a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given address
    /// `offset` is within the buffer and allows enough following space to point
    /// to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_at<U>(&self, offset: usize) -> Option<*const U> {
        let base = self.start() + offset;
        if self.check_bound(base + mem::size_of::<U>()) {
            return Some(base as *const U);
        }
        None
    }

    /// Returns a raw pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given pointer
    /// address `prev` is within the buffer and allows enough following space to
    /// point to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Option<*const U> {
        if self.check_bounds(prev as usize, prev as usize + mem::size_of::<T>()) {
            return self.ptr_at((prev as usize - self.start()) + mem::size_of::<T>());
        }
        None
    }

    /// Ensures that addresses `start` and `end` are within this buffer.
    #[inline]
    fn check_bounds(&self, start: usize, end: usize) -> bool {
        !(start >= end || start < self.start() || end > self.end())
    }

    /// Ensures that addresses `addr` is within this buffer.
    #[inline]
    fn check_bound(&self, addr: usize) -> bool {
        !(addr > self.end() || addr < self.start())
    }

    /// Returns a `slice` of `len` bytes starting at `offset` from the buffer
    #[inline]
    fn slice_at(&self, offset: usize, len: usize) -> &[u8] {
        unsafe {
            let base = self.start() + offset;
            if self.check_bounds(base, base + len) {
                // We can't use RawBuf::ptr_at here due to the BPF verifier which will reject
                let s = slice::from_raw_parts(base as *const _, len);
                return s;
            }
            &[]
        }
    }

    /// Returns the buffer as a `slice` of bytes
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.slice_at(0, self.len())
    }

    /// Loads Big Endian (BE, network-byte-order) data from the buffer,
    /// converting to host-byte-order prior to return.
    ///
    /// # Performance
    ///
    /// The default implementation performs a `memcpy` and performs
    /// bounds+alignment checking. Other implementors may use other indirect
    /// methods and omit or add additional safety checks. If one wishes to
    /// access the buffer directly without the `memcpy` see other methods such
    /// as [`RawBuf::ptr_at`]
    ///
    /// # Example
    ///
    /// ```no_run
    /// use core::mem;
    /// use memoffset::offset_of;
    /// use redbpf_probes::socket_filter::prelude::*;
    ///
    /// #[socket_filter]
    /// fn forward_tcp(skb: SkBuff) -> SkBuffResult {
    ///     let eth_len = mem::size_of::<ethhdr>();
    ///
    ///     // Load the protocols from the SkBuff
    ///     let eth_proto: u16 = skb.load_be(offset_of!(ethhdr, h_proto))?;
    ///     let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;
    ///
    ///     // only parse TCP
    ///     if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
    ///         return Ok(SkBuffAction::Ignore);
    ///     }
    ///     Ok(SkBuffAction::SendToUserspace)
    /// }
    /// ```
    #[inline]
    fn load_be<T: FromBe>(&self, offset: usize) -> Result<T> {
        self.load(offset).map(|val: T| val.from_be())
    }

    /// Loads data from the buffer.
    ///
    /// # Performance
    ///
    /// The default implementation performs a `memcpy` and performs
    /// bounds+alignment checking. Other implementors may use other indirect
    /// methods and omit or add additional safety checks. If one wishes to
    /// access the buffer directly without the `memcpy` see other methods such
    /// as [`RawBuf::ptr_at`]
    ///
    /// # Example
    ///
    /// ```no_run
    /// use core::mem;
    /// use memoffset::offset_of;
    /// use redbpf_probes::socket_filter::prelude::*;
    ///
    /// #[socket_filter]
    /// fn forward_tcp(skb: SkBuff) -> SkBuffResult {
    ///     let eth_len = mem::size_of::<ethhdr>();
    ///
    ///     // Load the protocols from the SkBuff
    ///     let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    ///     let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;
    ///
    ///     // only parse TCP
    ///     if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
    ///         return Ok(SkBuffAction::Ignore);
    ///     }
    ///     Ok(SkBuffAction::SendToUserspace)
    /// }
    /// ```
    #[inline]
    fn load<T>(&self, offset: usize) -> Result<T> {
        // @SAFETY
        //
        // Invariants that must be upheld for `T`:
        //
        // - Align of 1 (or #[repr(C, packed)]) in order to meet invariants listed below
        //
        // Invariants thats must be upheld for `MaybeUninit`
        //
        // - a variable of reference type must be aligned and non-NULL -
        // zero-initializing a variable of reference type causes instantaneous
        // undefined behavior, no matter whether that reference ever gets used
        // to access memory (see [Rust Docs for more
        // info](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#initialization-invariant))
        //
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
        // - `RawBuf::ptr_at` does bounds checking
        // - Alignment of pointers is checked
        unsafe {
            let mut data = mem::MaybeUninit::<T>::uninit();
            if let Some(ptr) = self.ptr_at::<T>(offset) {
                // We aren't checking that dst is not inside the buffer because
                // the only way for that happen is if someone we had a `RawBuf`
                // pointing to the current stack and the region requested
                // `offset + size_of::<T>()` overlapped with dst_ptr.
                let dst_ptr = data.as_mut_ptr();

                // @SAFETY check alignment
                if ptr as usize % mem::align_of::<T>() != 0
                    || dst_ptr as usize % mem::align_of::<T>() != 0
                {
                    return Err(Error::Unaligned);
                }

                ptr::copy_nonoverlapping(ptr, dst_ptr, mem::size_of::<T>());

                return Ok(data.assume_init());
            }
            Err(Error::LoadFailed)
        }
    }
}

/// Represents a raw mutable Buffer ("raw" meaning it works with, and gives out
/// raw mutable pointers) such as that pointed to by [`XdpContext`]. This trait
/// is meant to be a low level building block for higher level abstractions.
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait RawBufMut: RawBuf {
    /// Returns a raw mutable pointer to the address of `self.start() + offset`
    /// ensuring the remaining space is enough to point to a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given address
    /// `addr` is within the buffer and allows enough following space to point
    /// to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and pointed to
    /// address is a valid bit pattern of type `U` is left up to the caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_at_mut<T>(&self, offset: usize) -> Option<*mut T> {
        self.ptr_at_mut(self.start() + offset)
    }

    /// Returns a raw mutable pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given pointer
    /// address `prev` is within the buffer and allows enough following space to
    /// point to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_after_mut<T, U>(&self, prev: *const T) -> Option<*mut U> {
        self.ptr_at_mut(prev as usize + mem::size_of::<T>())
    }

    /// Returns a mutable `slice` of `len` bytes starting at `offset` from the
    /// buffer
    #[inline]
    fn slice_at_mut(&self, offset: usize, len: usize) -> &mut [u8] {
        unsafe {
            let start = self.start() + offset;
            if self.check_bounds(start, start + len) {
                if let Some(ptr) = self.ptr_at_mut(0) {
                    let s = slice::from_raw_parts_mut(ptr, len);
                    return s;
                }
            }
            &mut []
        }
    }

    /// Returns the buffer as a mutable `slice` of bytes
    #[inline]
    fn as_slice_mut(&self) -> &mut [u8] {
        self.slice_at_mut(0, self.len())
    }
}

/// A pointer to a Network Buffer of raw bytes that came off the wire. `T`
/// determines if the bytes are directly mutable (as in [`XdpContext`]) or not (
/// as in [`SkBuff`]). This struct keeps a cursor into the buffer to keep track
/// of currently parsed headers and the current offset of the next header and/or body.
pub struct NetBuf<'a, T: 'a + RawBuf> {
    /// The raw buffer of underlying memory and how all parsing will take place
    pub(crate) buf: *mut T,
    /// Offset from `buf.start()` where the next header/body begins
    pub(crate) nh_offset: usize,
    pub(crate) _marker: PhantomData<&'a mut T>,
}

impl<'a, T: 'a + RawBufMut> NetBuf<'a, T> {
    #[inline(always)]
    pub fn body_mut(&mut self) -> &mut [u8] {
        self.slice_at_mut(self.nh_offset, self.end() - (self.start() + self.nh_offset))
    }
}

impl<'a, T: RawBuf> RawBuf for NetBuf<'a, T> {
    #[inline(always)]
    fn start(&self) -> usize {
        if let Some(buf) = unsafe { self.buf.as_ref() } {
            return buf.start();
        }
        panic!("Pointer to RawBuf is null")
    }
    #[inline(always)]
    fn end(&self) -> usize {
        if let Some(buf) = unsafe { self.buf.as_ref() } {
            return buf.end();
        }
        panic!("Pointer to RawBuf is null")
    }
}

impl<'a, T: RawBufMut> RawBufMut for NetBuf<'a, T> {}

impl<'a, T: RawBuf> Packet<'a, T> for NetBuf<'a, T> {
    type Encapsulated = L2Proto<'a, T>;

    #[inline(always)]
    fn buf(self) -> NetBuf<'a, T> {
        self
    }

    #[inline(always)]
    fn buf_ref(&self) -> &NetBuf<'a, T> {
        self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.end() - (self.start() + self.offset())
    }

    #[inline(always)]
    fn offset(&self) -> usize {
        self.nh_offset
    }

    #[inline(always)]
    fn body(&self) -> &[u8] {
        self.slice_at(self.offset(), self.end() - (self.start() + self.offset()))
    }

    #[inline(always)]
    fn parse(self) -> Result<Self::Encapsulated> {
        Err(Error::UnsupportedMethod)
    }
}

unsafe impl<'a, T: RawBuf> FromBytes<'a, T> for NetBuf<'a, T> {
    #[inline(always)]
    fn from_bytes(buf: NetBuf<'a, T>) -> Result<Self> {
        Ok(buf)
    }
}
