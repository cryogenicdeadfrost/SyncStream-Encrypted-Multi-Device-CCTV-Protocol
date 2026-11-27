#pragma once

#include "syncstream/discovery.hpp"
#include "syncstream/secure_channel.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace syncstream {

enum class PairingMethod : std::uint8_t {
    usb_trusted = 1,
    confirmation_code = 2
};

struct PairingRequest {
    std::string device_id;
    PairingMethod method{PairingMethod::confirmation_code};
    std::string confirmation;
};

struct ProvisionedDevice {
    DeviceInfo info;
    std::array<std::uint8_t, key_len> session_key{};
    std::uint32_t credential_version{1};
};

class Bootstrap {
public:
    static std::string fingerprint(std::span<const std::uint8_t> public_identity);
    static bool verify_confirmation(std::string_view expected, std::string_view provided);
    static ProvisionedDevice provision(
        const DeviceInfo& device,
        std::span<const std::uint8_t> bootstrap_secret,
        PairingMethod method,
        std::string_view confirmation = {});
};

} // namespace syncstream
