// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod ipv4;

pub use ipv4::Ipv4;

use crate::{
    bindings::{IPPROTO_TCP, IPPROTO_UDP},
    net::{
        buf::{NetBuf, RawBuf},
        error::{Error, Result},
        layer4::{L4Proto, Tcp, Udp},
        FromBytes, Packet,
    },
};

// Because Rust enums have a size of their greatest variant we must ensure that
// all variants have the exact same size, otherewise the verifier may reject
// creation of this enum when smaller variants are used and padding bytes end up
// inserted.
//
// The way we do this is by each variant containing exactly two fields, a
// mutable raw pointer to the header from the kernel bindings, and the NetBuf it
// was created from.
/// An enum with variants for each Layer 3 protocol that can be encapsulted by Layer 2.
pub enum L3Proto<'a, T: RawBuf> {
    Ipv4(Ipv4<'a, T>),
    #[doc(hidden)]
    _NonExaustive,
}

impl<'a, T: RawBuf> L3Proto<'a, T> {
    #[inline(always)]
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L3Proto::Ipv4(ip) => ip.buf(),
            _ => unimplemented!(),
        }
    }

    #[inline(always)]
    fn inner_buf_ref(&self) -> &NetBuf<'a, T> {
        match self {
            L3Proto::Ipv4(ip)=> ip.buf_ref(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for L3Proto<'a, T> {
    type Encapsulated = L4Proto<'a, T>;

    #[inline(always)]
    fn buf(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }

    #[inline(always)]
    fn buf_ref(&self) -> &NetBuf<'a, T> {
        self.inner_buf_ref()
    }

    #[inline(always)]
    fn offset(&self) -> usize {
        self.inner_buf_ref().offset()
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner_buf_ref().end() - (self.inner_buf_ref().start() + self.offset())
    }

    #[inline(always)]
    fn body(&self) -> &[u8] {
        let buf = self.inner_buf_ref();
        buf.slice_at(self.offset(), buf.end() - (buf.start() + self.offset()))
    }

    #[inline(always)]
    fn parse(self) -> Result<Self::Encapsulated> {
        match self {
            L3Proto::Ipv4(ref ip) => match ip.protocol() {
                p if p as u32 == IPPROTO_TCP => {
                    return Ok(L4Proto::Tcp(Tcp::<T>::from_bytes(self.buf())?));
                }
                p if p as u32 == IPPROTO_UDP => {
                    return Ok(L4Proto::Udp(Udp::<T>::from_bytes(self.buf())?));
                }
                p => return Err(Error::UnimplementedProtocol(p as u32)),
            },
            _ => unreachable!(),
        }
    }
}
