# dhcp_replacement

## Prerequisites

1. Stable Rust toolchains: 
   ```
   rustup toolchain install stable
   ```

2. Nightly Rust toolchains: 
   ```
   rustup toolchain install nightly --component rust-src
   ```

3. (If cross-compiling) Rustup target:
   ```
   rustup target add ${ARCH}-unknown-linux-musl
   ```

4. (If cross-compiling) LLVM: 
   - on macOS: `brew install llvm`

5. (If cross-compiling) C toolchain:
   - on macOS: [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross)

6. bpf-linker: 
   ```
   cargo install bpf-linker
   ```
   (use `--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
#debug and parameter
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens33

#release
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens33
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package dhcp_replacement --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/dhcp_replacement` can be copied to a Linux server or VM and run there.

## Setup eBPF Development Environment on Linux

### Install dependencies for bpf-linker and bpftool

```shell
# Install LLVM and Clang
sudo apt-get update
sudo apt-get install llvm clang -y

# Install bpf-linker
cargo install bpf-linker

# Install bpftool
sudo apt install linux-tools-common linux-tools-$(uname -r) linux-cloud-tools-$(uname -r) -y
```

## Cross-compiling on Ubuntu

### Target Platform Information

For ARM platforms, you may use targets like `armv7-unknown-linux-gnueabihf`:

- **GNU**: Uses GNU toolchain and C library (typically glibc)
- **E**: Endianness (little-endian)
- **ABI**: Application Binary Interface
- **HF**: Hard Float (hardware floating point support)
  - Without "hf" (`gnueabi`) means using software-emulated floating point or passing floating point arguments via integer registers

### Determining Architecture Details

- Endianness can be tested with C or Rust programs
- Floating point support:
  1. Check `/proc/cpuinfo` for features like "vfp" or "neon"
  2. Use `readelf` to examine executable files on the target platform
  3. Use `cat /etc/os-release |grep ARCH`

### Setting Up Cross-Compilation

```shell
# Add the target architecture
rustup target add armv7-unknown-linux-gnueabihf

# Install LLVM
sudo apt-get install llvm

# Install ARM cross-compilation toolchain
sudo apt-get install gcc-arm-linux-gnueabihf
```

### Cross-Compilation Commands

For ARM with hardware floating point:
```shell
CC=arm-linux-gnueabihf-gcc cargo build --package dhcp_replacement --release \
  --target=armv7-unknown-linux-gnueabihf \
  --config=target.armv7-unknown-linux-gnueabihf.linker=\"arm-linux-gnueabihf-gcc\"
```

For ARM with software floating point:
```shell
CC=arm-linux-gnueabi-gcc cargo build --package dhcp_replacement --release \
  --target=armv7-unknown-linux-gnueabi \
  --config=target.armv7-unknown-linux-gnueabi.linker=\"arm-linux-gnueabi-gcc\"
```

### Static Linking for Target Platforms

If the target platform is missing dynamic libraries:
```shell
CC=arm-linux-gnueabi-gcc RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --package dhcp_replacement --release \
  --target=armv7-unknown-linux-gnueabi \
  --config=target.armv7-unknown-linux-gnueabi.linker=\"arm-linux-gnueabi-gcc\"
```
