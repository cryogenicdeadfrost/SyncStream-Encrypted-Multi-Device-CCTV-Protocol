#include "syncstream/edge_hub.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

int main() {
    try {
        const auto master = syncstream::mint_key();
        syncstream::EdgeHub phone(master, std::chrono::seconds(45), 4096, 64, 128);
        syncstream::EdgeHub relay(master, std::chrono::seconds(45), 4096, 64, 128);

        std::vector<std::uint8_t> salt{0x10, 0x20, 0x30, 0x40};
        std::vector<std::uint8_t> ctx{'c', 't', 'r', 'l'};
        phone.stage_key(7, salt, ctx, true);
        relay.stage_key(7, salt, ctx, true);

        phone.allow_cmd(syncstream::Cmd::sync);
        relay.allow_cmd(syncstream::Cmd::sync);

        syncstream::Ctrl ctrl{"ios-cam-12", syncstream::Cmd::sync, syncstream::now_ms(), {'4', 'k', ':', '6', '0'}};
        const auto env = phone.seal(ctrl);
        const auto out = relay.open(env);

        std::cout << "key_ver=" << env.key_ver << '\n';
        std::cout << "seq=" << env.env.seq << '\n';
        std::cout << "dev=" << out.dev << '\n';
        std::cout << "body=" << std::string(out.body.begin(), out.body.end()) << '\n';
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }
}
