# SyncStream API Guide

SyncStream is intended to feel like a conventional C++ SDK. Developers can include <syncstream/syncstream.hpp>, link SyncStream::syncstream, and use the same API whether the bytes eventually travel over BLE, TCP, WebSocket, QUIC, USB, or an in-process test harness.

This document describes the application-facing API. It is intentionally transport agnostic.

## 1. Install and include

CMake consumers can use:

~~~cmake
find_package(SyncStream CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE SyncStream::syncstream)
~~~

The installation also provides syncstream.pc for pkg-config based builds.

The recommended public include is:

~~~cpp
#include <syncstream/syncstream.hpp>
~~~

## 2. Create a shared key

For a lab or first integration:

~~~cpp
const auto key = syncstream::mint_key();
~~~

Both trusted endpoints need the same 256-bit key.

Production applications should provision a unique device key instead of copying one key into multiple devices.

## 3. Phone side

~~~cpp
syncstream::CameraClient phone(key);

const auto request = phone.make_request(
    "front-door",
    syncstream::Cmd::get_status
);

const auto wire = phone.seal_wire(request);
~~~

wire is an ordinary byte vector. The application can send it through any reliable byte transport.

## 4. Camera side

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

## 5. Response

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

## 6. Transport integration

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

## 7. Camera commands

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

## 8. Payload size

The high-level API defaults to a 4 KiB application payload. This is deliberately conservative for control messages.

Do not use SyncStream as a video encryption tunnel. For CCTV media, use an appropriate media protocol and secure transport. SyncStream should carry commands and state.

## 9. Wire compatibility

WireCodec provides the stable byte representation.

Applications should persist or transmit the encoded bytes, not C++ object memory layouts.

The wire format is explicitly versioned so a future protocol revision can reject incompatible messages instead of silently interpreting them incorrectly.

## 10. Error handling

The library uses exceptions for malformed messages, authentication failures, replay, timestamp violations, and invalid configuration.

A language binding can translate these into its native error/result model.

Never treat an exception as an indication that a command should automatically be retried. Authentication failure, replay, malformed input, timeout, and device rejection have different operational meanings.

## 11. Security boundary

SyncStream protects:

- Confidentiality
- Message integrity
- Message authenticity for holders of the shared key
- Replay detection within the configured replay-cache lifetime
- Timestamp freshness

The embedding application must provide:

- A transport implementation
- Media capture, encoding, streaming, and recording if video is required

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


## 12. Test without a camera or network

Build the standalone example:

~~~bash
cmake -S . -B build
cmake --build build --target syncstream_standalone_phone_test
./build/syncstream_standalone_phone_test
~~~

The example creates a client and simulated camera in one process. It verifies the public API, authenticated wire round-trip, request correlation, and response decoding. This is the fastest way to prove the SDK is installed and functioning before adding a real transport or camera.

## 13. Real camera capture example

The optional syncstream_capture_stream example uses OpenCV only as an application-side media adapter. SyncStream sends start_recording and stop_recording control messages while OpenCV opens the camera and handles frames. This demonstrates the intended separation between the secure control plane and the video data plane.
