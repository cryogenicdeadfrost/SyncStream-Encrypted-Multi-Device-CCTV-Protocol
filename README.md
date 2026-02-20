# SyncStream Encrypted Multi-Device CCTV Protocol

SyncStream is a C++20 security core for control-plane protection in multi-device CCTV systems. It now includes authenticated command middleware, key-rotation primitives, policy and rate enforcement, mobile-facing examples, and Linux subsystem deployment guides.

## What is implemented

- AES-256-GCM packet sealing and opening with authenticated additional data and strict size validation
- Secure memory cleansing for secret-bearing buffers
- Control middleware (`RelayCore`) for command envelope sealing, validation, replay blocking, and skew checks
- Key lifecycle module (`Keychain`) with HKDF-SHA256 staging and active key switching
- Higher-level relay layer (`EdgeHub`) for versioned envelopes, command allowlists, and token-bucket rate limiting
- Test suite for crypto roundtrip, tamper rejection, replay defense, skew enforcement, key rotation, policy gating, and rate gating
- CLI for key generation and payload verification
- Mobile bridge examples that simulate phone-to-relay command flow

## Repository layout

- `include/syncstream/secure_channel.hpp`: cryptographic primitive API
- `include/syncstream/middleware.hpp`: command middleware API
- `include/syncstream/keychain.hpp`: key derivation and version management
- `include/syncstream/edge_hub.hpp`: high-level relay security layer
- `src/secure_channel.cpp`: OpenSSL-backed AEAD implementation
- `src/middleware.cpp`: replay/skew/middleware envelope logic
- `src/keychain.cpp`: HKDF key staging and activation logic
- `src/edge_hub.cpp`: policy, rate, and versioned relay orchestration
- `examples/mobile_bridge.cpp`: baseline mobile integration example
- `examples/edge_hub_demo.cpp`: advanced key-versioned relay example
- `tests/*.cpp`: crypto, middleware, and high-level edge tests
- `docs/PROD_BLUEPRINT.md`: production architecture baseline
- `docs/MOBILE_INTEGRATION.md`: Android/iOS integration path
- `docs/WSL_DEPLOYMENT.md`: Linux subsystem and WSL deployment guide
- `docs/ADVANCED_LAYERS.md`: layered security and performance model

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Binaries

```bash
./build/syncstream_cli gen
./build/syncstream_mobile_bridge
./build/syncstream_edge_hub_demo
```

## Production-readiness checklist

- Key management integrated with KMS or HSM
- Device enrollment and revocation workflow
- Distributed replay cache for horizontally scaled relays
- TLS pinning and mTLS across service boundaries
- Observability and audit pipeline
- Fuzzing and negative security tests in CI

See:

- `docs/PROD_BLUEPRINT.md`
- `docs/MOBILE_INTEGRATION.md`
- `docs/WSL_DEPLOYMENT.md`
- `docs/ADVANCED_LAYERS.md`
