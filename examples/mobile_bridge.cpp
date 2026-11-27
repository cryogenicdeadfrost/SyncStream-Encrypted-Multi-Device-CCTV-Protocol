#include "syncstream/api.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    try {
        const auto key = syncstream::mint_key();

        syncstream::CameraClient phone(key);
        syncstream::CameraServer camera(key);

        const std::vector<std::uint8_t> settings{'1', '0', '8', '0', 'p', ':', '3', '0'};
        const auto wire = phone.make_command(
            "android-cam-a",
            syncstream::Cmd::set_stream,
            settings);

        const auto request = camera.open_wire(wire);

        std::cout << "request_id=" << request.request_id << '\n';
        std::cout << "device=" << request.device_id << '\n';
        std::cout << "cmd=" << static_cast<int>(request.command) << '\n';

        const auto response = camera.make_response(
            request,
            true,
            std::vector<std::uint8_t>{'o', 'k'});

        const auto result = phone.open_response(response);

        std::cout << "accepted=" << (result.accepted ? "true" : "false") << '\n';
        std::cout << "response=" << std::string(result.payload.begin(), result.payload.end()) << '\n';
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }
}
