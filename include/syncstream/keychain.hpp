#pragma once

#include "syncstream/secure_channel.hpp"

#include <array>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>

namespace syncstream {

class Keychain {
public:
    explicit Keychain(std::array<std::uint8_t, key_len> master);
    ~Keychain();
    Keychain(const Keychain&) = delete;
    Keychain& operator=(const Keychain&) = delete;

    void stage(std::uint32_t ver, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ctx);
    void activate(std::uint32_t ver);
    std::array<std::uint8_t, key_len> take(std::uint32_t ver) const;
    std::uint32_t active() const;

private:
    std::array<std::uint8_t, key_len> master_{};
    std::unordered_map<std::uint32_t, std::array<std::uint8_t, key_len>> slots_;
    std::uint32_t active_ = 0;
    mutable std::mutex mu_;
};

}
