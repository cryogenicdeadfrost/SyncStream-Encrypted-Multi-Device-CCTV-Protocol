# SyncStream Encrypted Multi-Device CCTV Protocol

SyncStream is now a hardened C++20 baseline for secure control-plane and packet-plane encryption in multi-device CCTV relays. This repository previously described goals only; it now ships a working cryptographic core with tests and a CLI harness.

## What is implemented

- AES-256-GCM packet sealing and opening with authenticated additional data and strict size validation
- Per-packet random nonce generation using OpenSSL CSPRNG
- Bounds checks for all OpenSSL integer conversion boundaries
- Secure memory cleansing for keys and plaintext buffers
- Strict compiler warning profile and CI-friendly CMake test integration
- CLI for key generation and local encrypt/decrypt validation

## Repository layout

- `include/syncstream/secure_channel.hpp`: public API for secure packet handling
- `src/secure_channel.cpp`: OpenSSL-backed implementation
- `src/main.cpp`: CLI tool
- `tests/secure_channel_test.cpp`: roundtrip, tamper, and hex utility tests
- `CMakeLists.txt`: build and test config

## Security posture upgrades

- Migrated from conceptual-only state to concrete authenticated encryption primitive
- Added fail-fast error handling for cryptographic context setup and final authentication
- Added explicit data zeroization paths for secret-bearing memory
- Added tamper-detection tests for ciphertext, AAD, and tag mutations

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## CLI usage

Generate a fresh 256-bit key:

```bash
./build/syncstream_cli gen
```

Encrypt and verify a message roundtrip:

```bash
./build/syncstream_cli <64_hex_key> <aad_text> <message_text>
```

## Next expansion track

- SRTP media transport module with key rotation windows
- mTLS-secured websocket signaling daemon with replay-safe command envelopes
- Device identity enrollment and revocation workflow
- Continuous fuzzing for packet parser and envelope decoding surface
