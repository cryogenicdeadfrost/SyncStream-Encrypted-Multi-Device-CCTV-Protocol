#include "syncstream/bootstrap.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace syncstream {

namespace {

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throw std::runtime_error("failed to allocate SHA-256 context");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, out.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 failed");
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

} // namespace

std::string Bootstrap::fingerprint(std::span<const std::uint8_t> public_identity) {
    return hex_of(sha256(public_identity));
}

bool Bootstrap::verify_confirmation(std::string_view expected, std::string_view provided) {
    if (expected.size() != provided.size()) return false;
    return CRYPTO_memcmp(expected.data(), provided.data(), expected.size()) == 0;
}

ProvisionedDevice Bootstrap::provision(
    const DeviceInfo& device,
    std::span<const std::uint8_t> bootstrap_secret,
    PairingMethod method,
    std::string_view confirmation) {
    if (device.device_id.empty()) throw std::invalid_argument("device id is required");
    if (bootstrap_secret.size() != key_len) throw std::invalid_argument("bootstrap secret must be 32 bytes");

    if (method == PairingMethod::confirmation_code) {
        if (confirmation.size() < 6 || confirmation.size() > 32) {
            throw std::invalid_argument("confirmation code length invalid");
        }
    }

    ProvisionedDevice out{device, {}, 1};
    std::copy(bootstrap_secret.begin(), bootstrap_secret.end(), out.session_key.begin());
    return out;
}

} // namespace syncstream
