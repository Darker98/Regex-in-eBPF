# Kernel-Space Pattern Matching with Aya XDP

Rust/Aya implementation where pattern matching algorithms are loaded from userspace into kernel BPF maps and executed at XDP layer.

## Architecture

```
Incoming Packets
       ↓
   [XDP Layer (Aya)] - Pattern matching in kernel
       ↓
   [BPF Maps] - Algorithm retrieved from map
       ↓
Match/Drop Decision
```

## Project Structure

- **ebpf/**: eBPF kernel program written in Rust using Aya
  - `src/main.rs`: XDP program with substring pattern matching
  - `Cargo.toml`: eBPF dependencies

- **userspace/**: Userspace loader and monitor
  - `src/main.rs`: Loads eBPF program, injects patterns into maps, monitors results
  - `Cargo.toml`: Runtime dependencies (aya, tokio)

## Build

```bash
cargo build --release
```

This produces:
- eBPF object file in `target/bpfeb-unknown-none/release/xdp_pattern_match`
- Userspace binary in `target/release/kernel-xdp`

## Usage

```bash
sudo ./target/release/kernel-xdp \
  --iface eth0 \
  --pattern "GET" \
  --ebpf ./target/bpfeb-unknown-none/release/xdp_pattern_match
```

This will:
1. Load the eBPF program into kernel
2. Store the pattern in the `ALGORITHM_MAP` BPF map
3. Attach XDP program to interface
4. Match incoming payloads against the pattern
5. Forward matching packets, drop non-matching ones

## Features

- **Aya Framework**: Safe Rust abstractions over eBPF
- **XDP Hook**: Kernel-space pattern matching at network layer
- **Dynamic Patterns**: Change patterns without recompiling XDP code
- **BPF Maps**: Store algorithms dynamically from userspace
- **Zero-copy**: Packets processed without context switches
- **Async Monitoring**: Tokio-based result monitoring

## Pattern Matching

- **Algorithm**: Substring matching (can be extended to full regex)
- **Performance**: Kernel-space execution = minimal latency
- **Results**: Match status stored in `RESULTS_MAP` for userspace access

## Real-world Extensions

- **regex crate in eBPF**: Use `regex_lite` or similar for kernel space
- **Complex algorithms**: Finite automata, DFA patterns
- **Statistics**: Count matches, track performance metrics
- **Per-packet context**: Store detailed match information

## Requirements

- Linux kernel with XDP support
- Rust toolchain with BPF target support
- LLVM with BPF backend
- Aya framework
