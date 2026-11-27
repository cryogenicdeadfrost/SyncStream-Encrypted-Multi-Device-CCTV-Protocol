#include <syncstream/syncstream.hpp>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    try {
        const auto key = syncstream::mint_key();
        syncstream::CameraClient phone(key);
        syncstream::CameraServer camera(key);

        const std::vector<std::uint8_t> payload{'p', 'i', 'n', 'g'};
        const auto request = phone.make_request(
            "local-test-camera",
            syncstream::Cmd::get_status,
            payload);

        const auto wire = phone.seal_wire(request);
        const auto decoded = camera.open_wire(wire);

        if (decoded.request_id != request.request_id ||
            decoded.device_id != "local-test-camera" ||
            decoded.command != syncstream::Cmd::get_status ||
            decoded.payload != payload) {
            throw std::runtime_error("request round-trip failed");
        }

        const std::vector<std::uint8_t> status{'o', 'n', 'l', 'i', 'n', 'e'};
        const auto response = camera.make_response(decoded, true, status);
        const auto result = phone.open_response(response);

        if (!result.accepted || result.request_id != request.request_id ||
            result.payload != status) {
            throw std::runtime_error("response round-trip failed");
        }

        std::cout << "SyncStream standalone phone test: PASS\n";
        std::cout << "request_id=" << request.request_id << '\n';
        std::cout << "device=" << request.device_id << '\n';
        std::cout << "wire_bytes=" << wire.size() << '\n';
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "SyncStream standalone phone test: FAIL: " << ex.what() << '\n';
        return 1;
    }
}
