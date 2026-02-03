# Userspace Pattern Matching with Aya XDP

Rust/Aya implementation where payloads are captured via XDP and sent to userspace for regex pattern matching.

## Architecture

```
Incoming Packets
       ↓
   [XDP Layer (Aya)] - Captures packets
       ↓
[Userspace Rust App] - Regex pattern matching
       ↓
   Return Result/Forward Packet
```

## Project Structure

- **ebpf/**: eBPF kernel program written in Rust using Aya
  - `src/main.rs`: XDP program that parses Ethernet/IP/TCP headers
  - `Cargo.toml`: eBPF dependencies

- **userspace/**: Userspace loader and pattern matcher
  - `src/main.rs`: Loads eBPF program, attaches to interface, pattern matches payloads
  - `Cargo.toml`: Runtime dependencies (aya, regex, tokio)

## Build

```bash
cargo build --release
```

This produces:
- eBPF object file in `target/bpfeb-unknown-none/release/xdp_redirect`
- Userspace binary in `target/release/userspace-xdp`

## Usage

```bash
sudo ./target/release/userspace-xdp \
  --iface eth0 \
  --pattern "GET|POST" \
  --ebpf ./target/bpfeb-unknown-none/release/xdp_redirect
```

## Features

- **Aya Framework**: Safe Rust abstractions over eBPF
- **XDP Hook**: Operates at the earliest network layer
- **Regex Matching**: Full regex support in userspace
- **Async Runtime**: Tokio-based event handling
- **Type-Safe**: Compile-time verification of eBPF interactions

## Real-world Enhancement

To receive actual packets in userspace, integrate:
- **AF_XDP sockets**: Zero-copy packet transmission
- **Perf buffers**: Event submission to userspace
- **Ring buffers**: Newer kernel event mechanism

## Requirements

- Linux kernel with XDP support
- Rust toolchain with BPF target support
- LLVM with BPF backend
