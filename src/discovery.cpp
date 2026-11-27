#include "syncstream/discovery.hpp"

#include <algorithm>
#include <stdexcept>

namespace syncstream {

StaticDiscovery::StaticDiscovery(std::vector<DeviceInfo> devices)
    : devices_(std::move(devices)) {}

std::vector<DeviceInfo> StaticDiscovery::scan() { return devices_; }

std::string capability_name(Capability capability) {
    switch (capability) {
        case Capability::status: return "status";
        case Capability::streaming: return "streaming";
        case Capability::recording: return "recording";
        case Capability::ptz: return "ptz";
        case Capability::audio: return "audio";
        case Capability::storage: return "storage";
    }
    return "unknown";
}

std::string transport_name(TransportKind kind) {
    switch (kind) {
        case TransportKind::usb: return "usb";
        case TransportKind::ble: return "ble";
        case TransportKind::wifi_direct: return "wifi-direct";
        case TransportKind::lan: return "lan";
        case TransportKind::tcp: return "tcp";
        case TransportKind::custom: return "custom";
    }
    return "unknown";
}

} // namespace syncstream
