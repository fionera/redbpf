// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Layer 2 frame handling
mod eth;

pub use eth::Ethernet;

use crate::{
    bindings::ETH_P_IP,
    net::{
        buf::{NetBuf, RawBuf},
        error::{Error, Result},
        layer3::{Ipv4, L3Proto},
        FromBytes, Packet,
    },
};

pub enum L2Proto<'a, T: RawBuf> {
    Ethernet(Ethernet<'a, T>),
    #[doc(hidden)]
    _NonExaustive
}

impl<'a, T: RawBuf> L2Proto<'a, T> {
    #[inline(always)]
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L2Proto::Ethernet(eth) => eth.buf(),
            _ => unimplemented!(),
        }
    }

    #[inline(always)]
    fn inner_buf_ref(&self) -> &NetBuf<'a, T> {
        match self {
            L2Proto::Ethernet(eth) => eth.buf_ref(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for L2Proto<'a, T> {
    type Encapsulated = L3Proto<'a, T>;

    #[inline(always)]
    fn buf(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }

    #[inline(always)]
    fn buf_ref(&self) -> &NetBuf<'a, T> {
        &self.inner_buf_ref()
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
            L2Proto::Ethernet(ref eth) => match eth.proto() {
                p if p as u32 == ETH_P_IP => {
                    return Ok(L3Proto::Ipv4(Ipv4::from_bytes(self.buf())?));
                }
                p => return Err(Error::UnimplementedProtocol(p as u32)),
            },
            _ => unreachable!(),
        }
    }
}
