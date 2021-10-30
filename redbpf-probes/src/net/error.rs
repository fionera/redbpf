// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::result::Result as StdResult;

pub enum Error {
    Other,
    /// The type requested from [`RawBuf::ptr_at`] failed bounds checking
    OutOfBounds,
    /// The type requested from `FromBytes::from_bytes` failed with an unknown
    /// error
    TypeFromBytes,
    UnknownProtocol,
    WrongProtocol,
    LoadFailed,
    /// The protocol found inside the network buffer has not been implemented
    /// yet
    UnimplementedProtocol(u32),
    /// A raw pointer was `null`
    NullPtr,
    /// Pointer access was unaligned
    Unaligned,
    /// The method called is unsuported by design, see the docs of the called
    /// method for more details
    UnsupportedMethod,
}

pub type Result<T> = StdResult<T, Error>;

