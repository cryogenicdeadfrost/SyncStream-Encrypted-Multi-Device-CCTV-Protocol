# SyncStream API Guide

This document describes the application-facing API. It is intentionally transport agnostic.

## 1. Create a shared key

For a lab or first integration:

~~~cpp
const auto key = syncstream::mint_key();
~~~

Both trusted endpoints need the same 256-bit key.

Production applications should provision a unique device key instead of copying one key into multiple devices.

## 2. Phone side

~~~cpp
syncstream::CameraClient phone(key);

const auto request = phone.make_request(
    "front-door",
    syncstream::Cmd::get_status
);

const auto wire = phone.seal_wire(request);
~~~

wire is an ordinary byte vector. The application can send it through any reliable byte transport.

## 3. Camera side

~~~cpp
syncstream::CameraServer camera(key);

const auto request = camera.open_wire(wire);

switch (request.command) {
case syncstream::Cmd::get_status:
    // Collect camera status.
    break;
case syncstream::Cmd::start_recording:
    // Start recording.
    break;
case syncstream::Cmd::stop_recording:
    // Stop recording.
    break;
default:
    // Reject commands unsupported by this camera.
    break;
}
~~~

The library authenticates the envelope, checks timestamp skew, rejects replay, and returns the authenticated command.

Application code must still perform authorization and capability checks. Encryption proves that the message was created by a holder of the configured key. It does not decide whether a particular human user is allowed to operate a particular camera.

## 4. Response

~~~cpp
const std::vector<std::uint8_t> status{
    'o', 'n', 'l', 'i', 'n', 'e'
};

const auto response = camera.make_response(
    request,
    true,
    status
);
~~~

The phone can authenticate and decode it:

~~~cpp
const auto result = phone.open_response(response);

if (result.accepted) {
    // Use result.payload.
}
~~~

The request ID is preserved across the request/response exchange.

## 5. Transport integration

SyncStream intentionally does not own sockets.

A transport adapter only needs to move bytes:

~~~text
CameraClient::seal_wire()
        |
        v
transport.send(bytes)
        |
        v
transport.receive()
        |
        v
CameraServer::open_wire()
~~~

Suitable transports include:

- WebSocket over TLS
- TCP with application framing
- QUIC
- BLE characteristics
- USB
- Unix domain sockets
- gRPC byte payloads
- A custom embedded transport

The same authenticated wire format is used regardless of transport.

## 6. Camera commands

The current command set is:

- arm
- disarm
- sync
- ping
- get_status
- set_stream
- start_recording
- stop_recording
- ptz

Command payloads are intentionally opaque to the cryptographic layer. A camera application can define its own payload schema, such as a small binary structure or JSON/CBOR/Protobuf document.

This keeps the security library independent from any particular camera vendor.

## 7. Payload size

The high-level API defaults to a 4 KiB application payload. This is deliberately conservative for control messages.

Do not use SyncStream as a video encryption tunnel. For CCTV media, use an appropriate media protocol and secure transport. SyncStream should carry commands and state.

## 8. Wire compatibility

WireCodec provides the stable byte representation.

Applications should persist or transmit the encoded bytes, not C++ object memory layouts.

The wire format is explicitly versioned so a future protocol revision can reject incompatible messages instead of silently interpreting them incorrectly.

## 9. Error handling

The library uses exceptions for malformed messages, authentication failures, replay, timestamp violations, and invalid configuration.

A language binding can translate these into its native error/result model.

Never treat an exception as an indication that a command should automatically be retried. Authentication failure, replay, malformed input, timeout, and device rejection have different operational meanings.

## 10. Security boundary

SyncStream protects:

- Confidentiality
- Message integrity
- Message authenticity for holders of the shared key
- Replay detection within the configured replay-cache lifetime
- Timestamp freshness

The embedding application must provide:

- User authentication
- User-to-device authorization
- Device enrollment
- Key provisioning
- Key storage
- Key revocation
- Persistent/shared replay state when required
- Transport availability
- Camera capability validation
- Camera credentials
- Audit logging

That boundary is intentional. SyncStream is a reusable protocol library, not an all-in-one surveillance product.
