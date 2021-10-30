// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod tcp;
mod udp;

use crate::net::{
    buf::{NetBuf, RawBuf},
    error::Result,
    Packet,
};

pub use self::{tcp::Tcp, udp::Udp};

pub enum L4Proto<'a, T: RawBuf> {
    Tcp(Tcp<'a, T>),
    Udp(Udp<'a, T>),
    #[doc(hidden)]
    _NonExaustive,
}

impl<'a, T: RawBuf> L4Proto<'a, T> {
    #[inline(always)]
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L4Proto::Tcp(tcp) => tcp.buf(),
            _ => unimplemented!(),
        }
    }

    #[inline(always)]
    fn inner_buf_ref(&self) -> &NetBuf<'a, T> {
        match self {
            L4Proto::Tcp(tcp) => tcp.buf_ref(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for L4Proto<'a, T> {
    type Encapsulated = NetBuf<'a, T>;

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
        Ok(self.inner_buf())
    }
}
