#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace syncstream {

enum class TransportKind : std::uint8_t {
    usb = 1,
    ble = 2,
    wifi_direct = 3,
    lan = 4,
    tcp = 5,
    custom = 255
};

struct TransportInfo {
    TransportKind kind{TransportKind::custom};
    std::string name;
    std::uint32_t mtu{0};
    bool reliable{false};
    bool encrypted_by_link{false};
};

class Transport {
public:
    virtual ~Transport() = default;
    virtual TransportInfo info() const = 0;
    virtual void send(std::span<const std::uint8_t> frame) = 0;
    virtual std::vector<std::uint8_t> receive() = 0;
    virtual bool connected() const = 0;
    virtual void close() noexcept = 0;
};

} // namespace syncstream
