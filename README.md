# SyncStream Encrypted Multi-Device CCTV Protocol

SyncStream is a C++20 security core for control-plane protection in multi-device CCTV systems. It now includes authenticated command middleware, anti-replay logic, mobile-facing envelope patterns, and Linux subsystem deployment guidance.

## What is implemented

- AES-256-GCM packet sealing and opening with authenticated additional data and strict size validation
- Secure memory cleansing for secret-bearing buffers
- Control middleware (`RelayCore`) for command envelope sealing, validation, replay blocking, and skew checks
- Test suite for crypto roundtrip, tamper rejection, replay defense, and timestamp enforcement
- CLI for key generation and payload verification
- Mobile bridge example that simulates phone-to-relay command flow

## Repository layout

- `include/syncstream/secure_channel.hpp`: cryptographic primitive API
- `include/syncstream/middleware.hpp`: command middleware API
- `src/secure_channel.cpp`: OpenSSL-backed AEAD implementation
- `src/middleware.cpp`: replay/skew/middleware envelope logic
- `src/main.cpp`: CLI
- `examples/mobile_bridge.cpp`: mobile integration example binary
- `tests/secure_channel_test.cpp`: crypto tests
- `tests/middleware_test.cpp`: middleware tests
- `docs/PROD_BLUEPRINT.md`: production architecture baseline
- `docs/MOBILE_INTEGRATION.md`: Android/iOS integration path
- `docs/WSL_DEPLOYMENT.md`: Linux subsystem and WSL deployment guide

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
```

## Middleware API quickstart

- Use `RelayCore::seal_ctrl` on producer side to generate secure `Env`
- Send `Env` over TLS websocket or gRPC stream
- Use `RelayCore::open_ctrl` on relay side to validate and unpack command
- Reject replay and clock skew automatically based on configured policy

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
