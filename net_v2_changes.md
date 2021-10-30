# Highlights

- Safe xdp_md refs
- RawBuf(Mut)
  -  Move `load`
- NetBuf
- Packet
- FromBytes
- Protocol Enums
- Protocol Header Wrappers
- Module Re-org
- XdpResult type change
- XdpAction::from_any

## Addresses Issues

- [#78 (The recommended way to modify
  packets?)](https://github.com/redsift/redbpf/issues/78)
  - Also [this comment from #78 (cohesive interface to both Socket and
    XDP)](https://github.com/redsift/redbpf/issues/78#issuecomment-726323918)
- Opens path to addressing [#87 (XDP program does not work on wireless
  interface)](https://github.com/redsift/redbpf/issues/87)
