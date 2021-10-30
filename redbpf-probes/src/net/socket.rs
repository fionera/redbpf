//! Socket related type and functions

use core::{
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};

use crate::{
    bindings::*,
    helpers::bpf_skb_load_bytes,
    net::{
        buf::{NetBuf, RawBuf},
        error::{Error, Result},
        FromBe,
    },
};

// Errors in socket-related programs
pub enum SocketError {
    /// Loading data from the socket buffer failed.
    LoadFailed,
}

/// Context object provided to Socket-related programs.
pub struct SkBuff {
    /// The low level skb instance.
    pub skb: *const __sk_buff,
}

impl SkBuff {
    /// Returns the `__sk_buff` context passed by the kernel.
    #[inline]
    pub fn inner(&mut self) -> &__sk_buff {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx;
        }
        panic!("*__sk_buff is null")
    }

    /// Returns a [`NetBuf`][0] with the header offset set to `0` since this is
    /// a clean slate data buffer with no knowledge of what type of data lives
    /// inside.
    #[inline(always)]
    pub fn data<'a>(&'a self) -> NetBuf<'a, Self> {
        NetBuf {
            buf: self as *const _ as *mut _,
            nh_offset: 0,
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").len }
    }

    #[inline(always)]
    pub fn pkt_type(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").pkt_type }
    }

    #[inline(always)]
    pub fn mark(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").mark }
    }

    #[inline(always)]
    pub fn queue_mapping(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").queue_mapping }
    }
    #[inline(always)]
    pub fn protocol(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").protocol }
    }

    /// Returns `true` if the VLAN tag is present
    #[inline(always)]
    pub fn vlan_present(&self) -> bool {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").vlan_present == 1 }
    }

    #[inline(always)]
    pub fn vlan_tci(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").vlan_tci }
    }
    #[inline(always)]
    pub fn vlan_proto(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").vlan_proto }
    }
    #[inline(always)]
    pub fn priority(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").priority }
    }
    #[inline(always)]
    pub fn ingress_ifindex(&self) -> u32 {
        unsafe {
            self.skb
                .as_ref()
                .expect("*__sk_buff is null")
                .ingress_ifindex
        }
    }
    #[inline(always)]
    pub fn tc_index(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").tc_index }
    }
    #[inline(always)]
    pub fn cb(&self) -> &[u32; 5] {
        unsafe { &self.skb.as_ref().expect("*__sk_buff is null").cb }
    }
    #[inline(always)]
    pub fn hash(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").hash }
    }
    #[inline(always)]
    pub fn tc_classid(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").tc_classid }
    }
    #[inline(always)]
    pub fn napi_id(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").napi_id }
    }
    #[inline(always)]
    pub fn family(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").family }
    }
    #[inline(always)]
    pub fn remote_ip4(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").remote_ip4 }
    }
    #[inline(always)]
    pub fn local_ip4(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").local_ip4 }
    }
    #[inline(always)]
    pub fn remote_ip6(&self) -> &[u32; 4] {
        unsafe { &self.skb.as_ref().expect("*__sk_buff is null").remote_ip6 }
    }
    #[inline(always)]
    pub fn local_ip6(&self) -> &[u32; 4] {
        unsafe { &self.skb.as_ref().expect("*__sk_buff is null").local_ip6 }
    }

    #[inline(always)]
    pub fn remote_port(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").remote_port }
    }
    #[inline(always)]
    pub fn local_port(&self) -> u32 {
        unsafe { self.skb.as_ref().expect("*__sk_buff is null").local_port }
    }
}

impl RawBuf for SkBuff {
    #[inline(always)]
    fn start(&self) -> usize {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx.data as usize;
        }
        panic!("*__sk_buff is null")
    }

    #[inline(always)]
    fn end(&self) -> usize {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx.data_end as usize;
        }
        panic!("*__sk_buff is null")
    }

    #[inline]
    fn load_be<T: FromBe>(&self, offset: usize) -> Result<T> {
        self.load(offset).map(|val: T| val.from_be())
    }

    #[inline]
    fn load<T>(&self, offset: usize) -> Result<T> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(Error::LoadFailed);
            }

            Ok(data.assume_init())
        }
    }
}
