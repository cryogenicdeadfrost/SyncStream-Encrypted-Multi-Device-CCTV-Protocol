#include "syncstream/middleware.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

std::vector<std::uint8_t> bytes_of(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

int main() {
    try {
        const auto key = syncstream::mint_key();
        syncstream::RelayCore phone_side(key, std::chrono::seconds(45));
        syncstream::RelayCore relay_side(key, std::chrono::seconds(45));

        syncstream::Ctrl ctrl{};
        ctrl.dev = "android-cam-a";
        ctrl.cmd = syncstream::Cmd::sync;
        ctrl.at_ms = syncstream::now_ms();
        ctrl.body = bytes_of("start:1080p:30fps");

        const auto env = phone_side.seal_ctrl(ctrl);
        const auto out = relay_side.open_ctrl(env);

        std::cout << "seq=" << env.seq << '\n';
        std::cout << "device=" << out.dev << '\n';
        std::cout << "cmd=" << static_cast<int>(out.cmd) << '\n';
        std::cout << "payload=" << std::string(out.body.begin(), out.body.end()) << '\n';
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }
}
