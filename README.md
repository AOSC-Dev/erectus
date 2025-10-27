# 🐵 Erectus

A simple ELF patcher to convert LoongArch64 ABI 1.0 C/C++ binaries to ABI 2.0 compatible binaries.

Usage: `erectus <path/to/input/elf/file> <path/to/output/elf/file>`.

Note that not all binaries are convertible or functional after conversion. Your Milage May Vary.

## How to Build

The patcher can be built on any little-endian systems (not limited to LoongArch systems), but the ELF input file
has to be of LoongArch64 architecture to make any sense.

Required build tools:

- CMake
- C Compiler that can understand C99 or newer (LoongArch64 cross-compiler needed if re-generating shim functions on a non-LoongArch system)
- C++ Compiler that can understand C++17 or newer
- Bash shell
- Python 3.10 or newer

Required external libraries:

- `libelf`

### Build on Windows (R)

If for some reason you want to build this on a Microsoft Windows(R) system, you will need to install `vcpkg` from <https://vcpkg.io/en/index.html>.
You will also need `clang` to build LoongArch64 shim function (if you choose to re-generate the shim functions).

Use `vcpkg install --triplet=x64-mingw-static` to install required external libraries. After installation finishes, use
`cmake . -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DCMAKE_TOOLCHAIN_FILE=/home/user/vcpkg/scripts/buildsystems/vcpkg.cmake` to configure the project.
Then use the normal CMake build process to proceed.
