#include "syncstream/secure_channel.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void need(bool ok, const std::string& msg) {
    if (!ok) {
        throw std::runtime_error(msg);
    }
}

std::vector<std::uint8_t> bytes_of(const std::string& text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void roundtrip_ok() {
    const auto key = syncstream::mint_key();
    syncstream::CipherRig rig(key);
    const auto aad = bytes_of("frame:42");
    const auto plain = bytes_of("edge-cam packet");

    const syncstream::Packet p = rig.seal(plain, aad);
    const syncstream::SecureBlob out = rig.open(p, aad);
    need(std::vector<std::uint8_t>(out.view().begin(), out.view().end()) == plain, "roundtrip mismatch");
}

void tamper_ciphertext_fails() {
    const auto key = syncstream::mint_key();
    syncstream::CipherRig rig(key);
    const auto aad = bytes_of("hdr");
    const auto plain = bytes_of("pixel-plane");

    syncstream::Packet p = rig.seal(plain, aad);
    p.body[0] ^= 0x01U;

    bool hit = false;
    try {
        static_cast<void>(rig.open(p, aad));
    } catch (...) {
        hit = true;
    }
    need(hit, "tamper was not detected");
}

void tamper_aad_fails() {
    const auto key = syncstream::mint_key();
    syncstream::CipherRig rig(key);
    const auto aad = bytes_of("stream:cam-7");
    const auto plain = bytes_of("motion-slice");

    const syncstream::Packet p = rig.seal(plain, aad);
    auto bad_aad = aad;
    bad_aad[0] ^= 0xFFU;

    bool hit = false;
    try {
        static_cast<void>(rig.open(p, bad_aad));
    } catch (...) {
        hit = true;
    }
    need(hit, "aad tamper was not detected");
}

void tamper_tag_fails() {
    const auto key = syncstream::mint_key();
    syncstream::CipherRig rig(key);
    const auto aad = bytes_of("meta");
    const auto plain = bytes_of("node-frame");

    syncstream::Packet p = rig.seal(plain, aad);
    p.mac[0] ^= 0x80U;

    bool hit = false;
    try {
        static_cast<void>(rig.open(p, aad));
    } catch (...) {
        hit = true;
    }
    need(hit, "tag tamper was not detected");
}

void hex_flow() {
    std::array<std::uint8_t, 4> src{0xDE, 0xAD, 0xBE, 0xEF};
    const std::string text = syncstream::hex_of(src);
    need(text == "deadbeef", "hex encoding mismatch");
    const auto back = syncstream::from_hex(text);
    need(back.size() == src.size(), "hex decode size mismatch");
    need(std::equal(back.begin(), back.end(), src.begin()), "hex decode data mismatch");
}

}

int main() {
    try {
        roundtrip_ok();
        tamper_ciphertext_fails();
        tamper_aad_fails();
        tamper_tag_fails();
        hex_flow();
        std::cout << "syncstream tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
