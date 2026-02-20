#include "syncstream/secure_channel.hpp"

#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace syncstream {
namespace {

using EvpPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

[[noreturn]] void toss(const std::string& msg) {
    throw std::runtime_error(msg);
}

void zero(std::span<std::uint8_t> data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
    }
}

void chk(int code, const char* msg) {
    if (code != 1) {
        toss(msg);
    }
}

void chk_open_ssl_size(std::size_t size, const char* label) {
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        toss(std::string(label) + " too large");
    }
}

std::uint8_t nib(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(10 + c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(10 + c - 'A');
    }
    toss("invalid hex character");
}

}

SecureBlob::SecureBlob(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

SecureBlob::SecureBlob(SecureBlob&& other) noexcept : data_(std::move(other.data_)) {}

SecureBlob& SecureBlob::operator=(SecureBlob&& other) noexcept {
    if (this != &other) {
        zero(data_);
        data_ = std::move(other.data_);
    }
    return *this;
}

SecureBlob::~SecureBlob() {
    zero(data_);
}

std::span<const std::uint8_t> SecureBlob::view() const {
    return data_;
}

std::vector<std::uint8_t> SecureBlob::take() {
    return std::move(data_);
}

CipherRig::CipherRig(std::array<std::uint8_t, key_len> key) : key_(key) {}

CipherRig::~CipherRig() {
    zero(key_);
}

Packet CipherRig::seal(std::span<const std::uint8_t> plain, std::span<const std::uint8_t> aad) const {
    chk_open_ssl_size(plain.size(), "plaintext");
    chk_open_ssl_size(aad.size(), "aad");

    Packet pack;
    chk(RAND_bytes(pack.nonce.data(), static_cast<int>(pack.nonce.size())), "nonce generation failed");
    pack.body.resize(plain.size());

    EvpPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        toss("cipher context allocation failed");
    }

    chk(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "encrypt init failed");
    chk(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(pack.nonce.size()), nullptr), "iv length setup failed");
    chk(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), pack.nonce.data()), "key setup failed");

    int out_len = 0;
    if (!aad.empty()) {
        chk(EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())), "aad encrypt failed");
    }

    chk(EVP_EncryptUpdate(ctx.get(), pack.body.data(), &out_len, plain.data(), static_cast<int>(plain.size())), "payload encrypt failed");
    int fin_len = 0;
    chk(EVP_EncryptFinal_ex(ctx.get(), pack.body.data() + out_len, &fin_len), "encrypt finalize failed");

    const std::size_t produced = static_cast<std::size_t>(out_len + fin_len);
    if (produced != pack.body.size()) {
        toss("unexpected ciphertext size");
    }

    chk(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(pack.mac.size()), pack.mac.data()), "tag read failed");
    return pack;
}

SecureBlob CipherRig::open(const Packet& pack, std::span<const std::uint8_t> aad) const {
    chk_open_ssl_size(pack.body.size(), "ciphertext");
    chk_open_ssl_size(aad.size(), "aad");

    std::vector<std::uint8_t> plain(pack.body.size());
    EvpPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        toss("cipher context allocation failed");
    }

    chk(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "decrypt init failed");
    chk(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(pack.nonce.size()), nullptr), "iv length setup failed");
    chk(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), pack.nonce.data()), "key setup failed");

    int out_len = 0;
    if (!aad.empty()) {
        chk(EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())), "aad decrypt failed");
    }

    chk(EVP_DecryptUpdate(ctx.get(), plain.data(), &out_len, pack.body.data(), static_cast<int>(pack.body.size())), "payload decrypt failed");
    auto tag = pack.mac;
    chk(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()), "tag setup failed");

    int fin_len = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), plain.data() + out_len, &fin_len);
    if (ok != 1) {
        zero(plain);
        toss("authentication failed");
    }

    const std::size_t produced = static_cast<std::size_t>(out_len + fin_len);
    if (produced != plain.size()) {
        zero(plain);
        toss("unexpected plaintext size");
    }

    return SecureBlob(std::move(plain));
}

std::array<std::uint8_t, key_len> mint_key() {
    std::array<std::uint8_t, key_len> key{};
    chk(RAND_bytes(key.data(), static_cast<int>(key.size())), "key generation failed");
    return key;
}

std::string hex_of(std::span<const std::uint8_t> data) {
    static constexpr char lut[] = "0123456789abcdef";
    std::string out;
    out.resize(data.size() * 2);
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[i * 2] = lut[data[i] >> 4];
        out[i * 2 + 1] = lut[data[i] & 0x0F];
    }
    return out;
}

std::vector<std::uint8_t> from_hex(const std::string& text) {
    if ((text.size() % 2U) != 0U) {
        toss("hex input must have even length");
    }
    std::vector<std::uint8_t> out;
    out.reserve(text.size() / 2U);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const std::uint8_t hi = nib(text[i]);
        const std::uint8_t lo = nib(text[i + 1]);
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

}
