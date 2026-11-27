# SyncStream Android Test Harness

This directory contains the first real-phone validation path for SyncStream.

The intended test topology is:

    Android phone
        |
        | Wi-Fi / LAN
        v
    syncstream_android_test_bridge
        |
        v
    SyncStream CameraServer

USB is used for the first development/debug cycle only: install the APK, collect logs with adb, and inspect the application while the phone is attached. The SyncStream control session itself is then exercised wirelessly over the local network.

## Requirements

- Android 7.0 / API 24 or newer
- Android Studio with the Android SDK and NDK
- CMake 3.22.1 or newer
- A laptop/PC on the same Wi-Fi/LAN as the phone
- A C++20 compiler and OpenSSL for the PC bridge

The sample deliberately uses a fixed test key. It is not a production credential.

## Build the PC bridge

From the repository root:

    cmake -S . -B build
    cmake --build build --target syncstream_android_test_bridge

Run:

    ./build/syncstream_android_test_bridge

The default TCP port is 39170.

Find the laptop IPv4 address, then enter it in the Android test application.

## Build the Android test application

Open `android-test/` in Android Studio and run the `app` configuration on a physical Android device.

The project uses minSdk 24, targetSdk 35, C++20 through the Android NDK, the repository SyncStream core directly through CMake, and JNI only as a thin Android boundary.

The application contains no second implementation of the SyncStream protocol. The C++ library performs the authenticated command processing.

## Basic test

1. Connect the Android phone to the PC with USB.
2. Enable developer mode and USB debugging.
3. Install/run the test APK from Android Studio.
4. Start `syncstream_android_test_bridge` on the PC.
5. Put the PC's LAN IPv4 address into the app.
6. Press Connect.
7. Press Ping / Status.
8. Confirm `SyncStream command accepted`.

The USB cable is not part of the control path after deployment. Disconnect it and repeat the test while both devices remain on the same Wi-Fi network.

## What this proves

The test validates Android 7+ packaging, JNI to the C++ SyncStream core, TCP transport framing, authenticated SyncStream encryption, request IDs, sequence numbers, timestamp validation, replay protection, camera-side command decoding, response authentication, and Android-to-PC wireless operation.

It does not yet claim automatic BLE/Wi-Fi Direct discovery. Those are transport adapters above the transport-neutral core and should be added without changing the protocol.

## Debugging

Android:

    adb logcat | grep -i syncstream

PC:

    ./build/syncstream_android_test_bridge

Protocol debugging should inspect state transitions rather than plaintext secrets. Never print production keys, plaintext camera credentials, or private identity material.

For packet failures, first verify:

1. Phone and PC are on the same network.
2. TCP/39170 is reachable.
3. Both sides use the same test key.
4. Device ID is `SS-TEST-001`.
5. The bridge is using the current SyncStream version.
6. The error is not caused by clock skew or a replayed frame.

## Production transition

The test bridge is intentionally simple. Production should replace it with a real camera-side SyncStream agent and a transport adapter selected by the connection manager.

The intended progression is:

    USB debug
        ->
    LAN wireless test
        ->
    BLE/Wi-Fi Direct discovery
        ->
    authenticated pairing
        ->
    provisioned per-device credential
        ->
    automatic wireless reconnect
        ->
    real camera/media adapter