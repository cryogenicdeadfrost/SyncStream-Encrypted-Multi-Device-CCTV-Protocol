#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace syncstream {

inline constexpr std::size_t key_len = 32;
inline constexpr std::size_t nonce_len = 12;
inline constexpr std::size_t tag_len = 16;

class SecureBlob {
public:
    SecureBlob() = default;
    explicit SecureBlob(std::vector<std::uint8_t> data);
    SecureBlob(SecureBlob&& other) noexcept;
    SecureBlob& operator=(SecureBlob&& other) noexcept;
    SecureBlob(const SecureBlob&) = delete;
    SecureBlob& operator=(const SecureBlob&) = delete;
    ~SecureBlob();

    std::span<const std::uint8_t> view() const;
    std::vector<std::uint8_t> take();

private:
    std::vector<std::uint8_t> data_;
};

struct Packet {
    std::array<std::uint8_t, nonce_len> nonce{};
    std::vector<std::uint8_t> body;
    std::array<std::uint8_t, tag_len> mac{};
};

class CipherRig {
public:
    explicit CipherRig(std::array<std::uint8_t, key_len> key);
    CipherRig(const CipherRig&) = delete;
    CipherRig& operator=(const CipherRig&) = delete;
    CipherRig(CipherRig&&) = delete;
    CipherRig& operator=(CipherRig&&) = delete;
    ~CipherRig();

    Packet seal(std::span<const std::uint8_t> plain, std::span<const std::uint8_t> aad) const;
    SecureBlob open(const Packet& pack, std::span<const std::uint8_t> aad) const;

private:
    std::array<std::uint8_t, key_len> key_{};
};

std::array<std::uint8_t, key_len> mint_key();
std::string hex_of(std::span<const std::uint8_t> data);
std::vector<std::uint8_t> from_hex(const std::string& text);

}
