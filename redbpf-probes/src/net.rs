// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Types and traits for working with networking data.

The main trait exported by this module is `NetworkBuffer`. It's implemented
by
[`XdpContext`](https://ingraind.org/api/redbpf_probes/xdp/struct.XdpContext.html)
to provide access to the network data.
 */

mod buf;
pub mod error;
mod layer2;
mod layer3;
mod layer4;
pub mod socket;
pub mod socket_filter;
pub mod tc;
pub mod xdp;

/// A convienience prelude to glob import all supported protocols.
pub mod protocols {
    pub use super::layer2::*;
    pub use super::layer3::*;
    pub use super::layer4::*;
}

use crate::net::{
    buf::{NetBuf, RawBuf},
    error::Result,
};

/// A marker trait to mark types thats are aligned (have an alignment of 1).
///
/// Types can be marked to have an alignment of 1 either via `#[repr(align(1))]`
/// or `#[repr(C, packed)]`. A struct marked as `Unaligned` should also require
/// that all fields are `Unaligned` as well.
pub unsafe trait Unaligned {}

pub trait FromBe {
    fn from_be(&self) -> Self;
}

macro_rules! impl_from_be {
    ($T:ty) => {
        impl FromBe for $T {
            #[inline(always)]
            fn from_be(&self) -> $T {
                <$T>::from_be(*self)
            }
        }
    };
}

impl_from_be!(u8);
impl_from_be!(u16);
impl_from_be!(u32);

/// A `Packet` is an abstract idea of bytes coming off the wire making a network
/// message. `Packet`s are recursive (i.e. they encapsulate other `Packet`s).
///
/// An example is an [`Ethernet`] frame which then encapsulates an [`Ipv4`]
/// packet, which further encapsulates a [`Tcp`] a segment, finllay containing
/// some application payload.
///
/// ```no_run
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
/// ```
///
/// All implementors of this trait contain an underlying buffer ([`DataBuf`])
/// which represents the actual bytes on the wire. In some BPF contexts the
/// bytes in the buffer are the actual bytes from the network packet and thus
/// directly mutable while in other contexts the bytes only represent the in
/// kernel bytes and must be mutated via BPF helper functions.
///
/// This trait consists of several methods, one to access and pass on the
/// underlying buffer in order to pass it down the stack into the encapsulated
/// packet.
///
/// Another to "parse" the bytes at the current position of the buffer as some
/// further encapsulated packets. For example, if we have an [`Ethernet`] frame,
/// and call [`Packet::parse<Ipv4>`] (requesting an [`Ipv4`] packet), the bytes
/// at the current position of the underlying buffer are interpretted as the
/// requested packet type, and the position in the buffer is advanced to the end
/// of requested packet header.
///
/// ```
/// Currently have an Ethernet frame:
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///            ^~~ Current position
///
/// After calling Ethernet::parse<Ipv4>()
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///                 ^~~ Current position
///
/// After calling Ipv4::parse<Tcp>()
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///                       ^~~ Current position
/// ```
///
/// The `Packet::parse` method is fallible so that if the requested packet type
/// does not match the bytes in the buffer, the caller can be notified. However,
/// not all implementors have good methods to determine if the bytes in the
/// buffer match the requested type (assuming the buffer contains at least
/// enough remaining bytes to satisfy the request). Such an example would be
/// when requesting a [`Ethernet`] frame from a bare [`DataBuf`]. In such
/// circumstances it is up to the caller to ensure the returned structure is a
/// valid instance of the requested type.
///
/// In order to implement [`Packet::parse`] the requested type must meet a few invariants:
///
/// * Must have an alignment of 1 (or use `#[repr(C, packed)]`, which uses an
///   alignment of 1)
/// * Must also implement `Packet`
pub trait Packet<'a, T>: Sized
where
    T: RawBuf + 'a,
{
    type Encapsulated;

    /// Give up ownership of the underlying buffer where the cursor is currently
    /// pointing to body/next header.
    fn buf(self) -> NetBuf<'a, T>;

    /// Give a reference to the underlying buffer where the cursor is currently
    /// pointing to body/next header.
    fn buf_ref(&self) -> &NetBuf<'a, T>;

    /// Returns the offset from the start of the underlying buffer to the current 
    /// packet body/next header
    fn offset(&self) -> usize;

    /// Returns a slice to the body of the packet
    fn body(&self) -> &[u8];

    /// Returns the length (in bytes) the packet body
    /// 
    /// Equivalent to the underlying buffer length minus all currently parsed headers
    fn len(&self) -> usize;

    /// Interprets the first `size_of::<U>()` bytes in this buffer as some type
    /// `U`, "consuming" `size_of::<U>()` bytes from the buffer.
    #[inline(always)]
    fn parse_as<U>(self) -> Result<U>
    where
        U: FromBytes<'a, T>,
    {
        U::from_bytes(self.buf())
    }

    /// Parses the next bytes of a [`NetBuf`] as some further encapsulated
    /// packet type.
    ///
    /// Implementors should perform all safety to checks to ensure that the
    /// bytes being parsed represent a valid return type, and check all bounds.
    ///
    /// If multiple inner packet types are possible (such as Ethernet can
    /// encapsulate both TCP or UDP) then `Packet::Encapsulated` should be an
    /// enum which contains variants for all supported encapsulated protocols.
    ///
    /// For example, if we have a [`Ethernet`] and are unsure whether the next
    /// encapsulated packet is a [`Tcp`] or [`Udp`], but this can be determined
    /// by looking at [`Ethernet::proto`]. This method is implemented on
    /// [`Ethernet`] in such a manner as to look at the `proto` field and return
    /// the correct variant based on the `proto` value.
    ///
    /// **PRO TIP:** If `Packet::Encapsulated` could potentially have additional
    /// protocols or variants added later it should be a [non-exhaustive][0]
    /// enums, or hidden variants (`#[doc(hidden)]`) if required to support a
    /// `rustc` older than 1.40.
    ///
    /// [0]: https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute
    fn parse(self) -> Result<Self::Encapsulated>;
}

pub unsafe trait FromBytes<'a, T>: Sized
where
    T: RawBuf + 'a,
{
    fn from_bytes(buf: NetBuf<'a, T>) -> Result<Self>;
}
