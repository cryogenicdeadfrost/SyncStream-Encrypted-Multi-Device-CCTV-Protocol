# SyncStream Protocol and Reliability Model

SyncStream is a control-plane protocol. Media remains outside the protocol core.

## Connection lifecycle

    DISCOVER
       |
       v
    IDENTIFY
       |
       v
    PAIR / PROVISION
       |
       v
    AUTHENTICATE
       |
       v
    SESSION
       |
       v
    COMMAND / EVENT
       |
       v
    HEARTBEAT / RECOVERY
       |
       +----> RECONNECT
       |
       +----> RE-PROVISION when credentials are revoked

Discovery data is treated as untrusted metadata until the device identity and secure session are verified.

## Security

The existing SyncStream data plane uses AES-256-GCM with a 256-bit key, fresh 96-bit nonce, authenticated additional data, authentication tag, sequence number, timestamp, replay cache, bounded payloads, and strict wire-version checks.

The discovery layer does not replace authenticated encryption.

The pairing layer is deliberately separated from the session layer. A future production enrollment implementation should use device identity keys plus authenticated ECDH and an out-of-band confirmation or trusted USB bootstrap. A broadcast BLE advertisement must never contain a private key or long-lived symmetric secret.

## Hashing

SHA-256 fingerprints are intended for device identity display and diagnostic correlation. A fingerprint is not a substitute for authentication.

The secure decision is made from authenticated protocol messages, not from an untrusted hash supplied by a peer.

## Fault tolerance

Transport failures are expected.

A production connection manager should support heartbeat intervals, bounded receive timeouts, reconnect with exponential backoff, jitter to avoid synchronized reconnect storms, duplicate request suppression, idempotency metadata for safe command replay, session expiration, credential rotation, bounded frame and queue sizes, graceful transport shutdown, and explicit degraded/offline state.

Commands that cause irreversible hardware actions must not be blindly replayed after an uncertain transport failure.

For example, `get_status` can normally be retried. `start_recording` should use a request ID and device-side idempotency tracking before automatic retry.

## Bridge framing

The development Android bridge uses:

    uint32_be frame_length
    SyncStream wire frame

The bridge framing is not the security boundary. The inner SyncStream frame is.

The bridge rejects zero-length, oversized, truncated, or malformed frames before passing them to CameraServer.

## Transport independence

The protocol core does not require TCP.

A transport adapter can provide USB, BLE, Wi-Fi Direct, LAN/TCP, WebSocket, QUIC, or a custom embedded link.

The same authenticated SyncStream command envelope can travel over each adapter.

## Android strategy

The Android package should remain a thin platform adapter. The C++ SyncStream core owns protocol logic.

The Android layer owns lifecycle, permissions, platform discovery APIs, sockets/Bluetooth/USB APIs, secure platform credential storage, JNI/Kotlin API surface, and foreground/background execution policy.

This separation keeps Android-specific behavior out of the reusable protocol implementation.