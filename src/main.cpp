#include "syncstream/secure_channel.hpp"
#include <algorithm>

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::array<std::uint8_t, 32> key_from_hex(const std::string& text) {
    const std::vector<std::uint8_t> raw = syncstream::from_hex(text);
    if (raw.size() != 32U) {
        throw std::runtime_error("key must be 32 bytes encoded as 64 hex chars");
    }
    std::array<std::uint8_t, 32> out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

std::vector<std::uint8_t> bytes_of(const std::string& text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

}

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "gen") {
            const auto key = syncstream::mint_key();
            std::cout << syncstream::hex_of(key) << '\n';
            return 0;
        }

        if (argc != 4) {
            std::cerr << "Usage:\n";
            std::cerr << "  syncstream_cli gen\n";
            std::cerr << "  syncstream_cli <hex_key> <aad> <message>\n";
            return 1;
        }

        const std::array<std::uint8_t, 32> key = key_from_hex(argv[1]);
        syncstream::CipherRig rig(key);

        const auto aad = bytes_of(argv[2]);
        const auto plain = bytes_of(argv[3]);
        const syncstream::Packet pack = rig.seal(plain, aad);
        const syncstream::SecureBlob out = rig.open(pack, aad);

        std::cout << "nonce=" << syncstream::hex_of(pack.nonce) << '\n';
        std::cout << "cipher=" << syncstream::hex_of(pack.body) << '\n';
        std::cout << "tag=" << syncstream::hex_of(pack.mac) << '\n';
        std::cout << "plain=" << std::string(out.view().begin(), out.view().end()) << '\n';
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }
}
