#include "syncstream/keychain.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdexcept>

namespace syncstream {
namespace {

[[noreturn]] void die(const std::string& msg) {
    throw std::runtime_error(msg);
}

void clean(std::span<std::uint8_t> data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
    }
}

void chk(int code, const char* msg) {
    if (code != 1) {
        die(msg);
    }
}

}

Keychain::Keychain(std::array<std::uint8_t, key_len> master) : master_(master) {}

Keychain::~Keychain() {
    clean(master_);
    std::scoped_lock lock(mu_);
    for (auto& [_, key] : slots_) {
        clean(key);
    }
}

void Keychain::stage(std::uint32_t ver, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ctx) {
    if (ver == 0) {
        die("key version cannot be zero");
    }

    std::array<std::uint8_t, key_len> out{};
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        die("hkdf fetch failed");
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        die("hkdf context failed");
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string("key", master_.data(), master_.size()),
        OSSL_PARAM_construct_octet_string("salt", const_cast<unsigned char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string("info", const_cast<unsigned char*>(ctx.data()), ctx.size()),
        OSSL_PARAM_construct_end()};

    const int ok = EVP_KDF_derive(kctx, out.data(), out.size(), params);
    EVP_KDF_CTX_free(kctx);
    chk(ok, "hkdf derive failed");

    std::scoped_lock lock(mu_);
    slots_[ver] = out;
}

void Keychain::activate(std::uint32_t ver) {
    std::scoped_lock lock(mu_);
    if (slots_.find(ver) == slots_.end()) {
        die("key version not staged");
    }
    active_ = ver;
}

std::array<std::uint8_t, key_len> Keychain::take(std::uint32_t ver) const {
    std::scoped_lock lock(mu_);
    const auto it = slots_.find(ver);
    if (it == slots_.end()) {
        die("key version unknown");
    }
    return it->second;
}

std::uint32_t Keychain::active() const {
    std::scoped_lock lock(mu_);
    if (active_ == 0) {
        die("no active key");
    }
    return active_;
}

}
