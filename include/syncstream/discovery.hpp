#pragma once

#include "syncstream/transport.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace syncstream {

enum class DeviceType : std::uint8_t {
    camera = 1,
    gateway = 2,
    unknown = 255
};

enum class Capability : std::uint8_t {
    status = 1,
    streaming = 2,
    recording = 3,
    ptz = 4,
    audio = 5,
    storage = 6
};

struct DeviceInfo {
    std::string device_id;
    std::string name;
    DeviceType type{DeviceType::unknown};
    std::uint16_t protocol_major{1};
    std::uint16_t protocol_minor{0};
    std::vector<Capability> capabilities;
    std::vector<TransportKind> transports;
    std::array<std::uint8_t, 32> identity_fingerprint{};
};

class DiscoveryProvider {
public:
    virtual ~DiscoveryProvider() = default;
    virtual std::vector<DeviceInfo> scan() = 0;
};

class StaticDiscovery final : public DiscoveryProvider {
public:
    explicit StaticDiscovery(std::vector<DeviceInfo> devices);
    std::vector<DeviceInfo> scan() override;

private:
    std::vector<DeviceInfo> devices_;
};

std::string capability_name(Capability capability);
std::string transport_name(TransportKind kind);

} // namespace syncstream
