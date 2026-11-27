#include "syncstream/api.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void need(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}

void api_roundtrip() {
    const auto key = syncstream::mint_key();
    syncstream::CameraClient phone(key);
    syncstream::CameraServer camera(key);

    const std::vector<std::uint8_t> payload{'1', '0', '8', '0', 'p', ':', '3', '0'};
    const auto wire = phone.make_command("cam-01", syncstream::Cmd::set_stream, payload);
    const auto request = camera.open_wire(wire);

    need(!request.request_id.empty(), "request id missing");
    need(request.device_id == "cam-01", "device id mismatch");
    need(request.command == syncstream::Cmd::set_stream, "command mismatch");
    need(request.payload == payload, "payload mismatch");

    const std::vector<std::uint8_t> status{'o', 'k'};
    const auto response_wire = camera.make_response(request, true, status);
    const auto response = phone.open_response(response_wire);

    need(response.request_id == request.request_id, "response request id mismatch");
    need(response.device_id == request.device_id, "response device mismatch");
    need(response.accepted, "response was not accepted");
    need(response.payload == status, "response payload mismatch");
}

void wire_tamper_and_truncation_fail() {
    const auto key = syncstream::mint_key();
    syncstream::CameraClient phone(key);
    syncstream::CameraServer camera(key);

    auto wire = phone.make_command("cam-02", syncstream::Cmd::ping);
    wire.back() ^= 0x01U;

    bool tamper_hit = false;
    try {
        static_cast<void>(camera.open_wire(wire));
    } catch (...) {
        tamper_hit = true;
    }
    need(tamper_hit, "tampered wire was accepted");

    wire = phone.make_command("cam-02", syncstream::Cmd::ping);
    wire.pop_back();

    bool truncation_hit = false;
    try {
        static_cast<void>(camera.open_wire(wire));
    } catch (...) {
        truncation_hit = true;
    }
    need(truncation_hit, "truncated wire was accepted");
}

void replay_is_blocked_after_authentication() {
    const auto key = syncstream::mint_key();
    syncstream::CameraClient phone(key);
    syncstream::CameraServer camera(key);

    const auto wire = phone.make_command("cam-03", syncstream::Cmd::ping);
    static_cast<void>(camera.open_wire(wire));

    bool replay_hit = false;
    try {
        static_cast<void>(camera.open_wire(wire));
    } catch (...) {
        replay_hit = true;
    }
    need(replay_hit, "replay was accepted");
}

}

int main() {
    try {
        api_roundtrip();
        wire_tamper_and_truncation_fail();
        replay_is_blocked_after_authentication();
        std::cout << "syncstream API tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
