# Mobile Integration Guide

## Android and iOS mapping

- Keep transport socket in native stack
- Serialize SyncStream Env into protobuf or flatbuffer envelope
- Use RelayCore on gateway side to unwrap and validate envelope
- Keep device id stable and signed into enrollment workflow

## Minimal envelope schema

- `seq`: uint64
- `at_ms`: uint64
- `nonce`: 12 bytes
- `cipher`: bytes
- `mac`: 16 bytes

## Android side flow

1. Capture command from UI or camera lifecycle event
2. Build control payload bytes
3. Call native wrapper around `RelayCore::seal_ctrl`
4. Send envelope through TLS websocket
5. Handle ack from relay with sequence verification

## iOS side flow

1. Use Swift wrapper calling C++ bridge with Objective-C++
2. Keep key in Secure Enclave wrapped form
3. Seal command with monotonic timestamp source
4. Push envelope through URLSession websocket

## Reliability knobs

- Retry on network fail with same logical command but fresh timestamp and sequence
- Reject local clock drift over configured threshold
- Persist last ack sequence to detect out-of-order state after reconnect
