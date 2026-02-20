# Advanced Layers

## Security layers

- HKDF-backed key staging and activation via `Keychain`
- Versioned control envelopes via `VersionedEnv` with explicit key version routing
- Replay and skew checks inherited from `RelayCore`
- Command policy allowlist and per-device token-bucket rate control in `EdgeHub`

## Expansion model

- Keep media plane on SRTP/WebRTC
- Keep control plane on TLS websocket/gRPC with `VersionedEnv` payloads
- Roll key versions forward with overlapping acceptance windows
- Run per-tenant policy and rate settings at the relay edge

## Performance profile

- Core operations are in-process C++ with no heap-heavy serialization framework
- Envelope packing uses contiguous binary vectors
- Key derivation uses OpenSSL HKDF and can be pre-staged before traffic spikes
