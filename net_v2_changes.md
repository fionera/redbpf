# Renamed

The following were renamed/moved to follow Rust naming conventions and idioms

- `net::NetworkBuffer` -> `net::buf::RawBuf` (exposed as `net::RawBuf`)
- `net::NetworkError` -> `net::error::Error` (exposed as `net::Error`)
- `net::NetworkResult` -> `net::error::Result` (exposed as `net::Result`)

# Moved

All code under `redbpf-probes/src/net.rs` has been moved and split accross
`redbpf-probes/src/net/` to allow more separation and future expansion.

# Core Changes

The following core changes were made.

## `net::RawBuf` (previously `net::NetworkBuffer`)

In addition the name change, the following changes were made:

- REMOVES: trait bounds `Self: Sized + Clone`
  - It is more idiomatic to require `Sized` or specific bounds on trait methods,
    than the entire trait implementor
- ADDS: trait and method documentation
  - The top level trait, as well as all methods have been documented to include
    `# Safety` sections for `unsafe` methods
- RENAMES: `data_start` -> `start`
  - `net::RawBuf` has no knowledge of packet internals yet, this was moved to
    `??????????`. Thus only start and end address of the entire buffer are known
- RENAMES: `data_end` -> `end`
  - `net::RawBuf` has no knowledge of packet internals yet, this was moved to
    `??????????`. Thus only start and end address of the entire buffer are known
- MODIFIES: `net::RawBuf::check_bounds`
  - Condenses the `if` statement
- ADDS: `ptr_at_mut` and `ptr_after_mut`
  - Returns raw mutable pointers
