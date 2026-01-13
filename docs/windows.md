# Windows Build Instructions

## Prerequisites
To build `connect-ip-rust-scion` on Windows, you need to have the following installed.
- [Rust and Cargo](https://www.rust-lang.org/tools/install)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- [CMake](https://cmake.org/download/) (for `quiche` crate)
- [Protobuf Compiler](https://protobuf.dev/installation/) (for `scion-sdk` crate)
- [Npcap](https://npcap.com/#download) (for `pnet` crate)
- [NASM](https://www.nasm.us/) (for `quiche` crate)

- For the `pnet` crate the `Packet.lib` from the WinPcap Developers Pack is needed. Further information can be found [here](https://github.com/libpnet/libpnet?tab=readme-ov-file#windows).


## Building
Once the prerequisites are installed, you can build the project using Cargo.
```console
cargo build
```


# Running on Windows
Running on Windows requires the following to be present.
- Administrator privileges (required for creating TUN interfaces)
- `wintun.dll` in the same directory as the executable (for TUN support). The DLL can be downloaded from the [Wintun releases](https://www.wintun.net/#downloads) page.
