#include "syncstream/connection.hpp"

#include <algorithm>
#include <stdexcept>

namespace syncstream {

CameraConnection::CameraConnection(
    DeviceInfo info,
    std::unique_ptr<Transport> transport,
    CameraClient client)
    : info_(std::move(info)), transport_(std::move(transport)), client_(std::move(client)) {
    if (!transport_) throw std::invalid_argument("transport is required");
}

const DeviceInfo& CameraConnection::info() const noexcept { return info_; }

TransportKind CameraConnection::transport_kind() const noexcept {
    return transport_->info().kind;
}

bool CameraConnection::connected() const noexcept { return transport_->connected(); }

std::vector<std::uint8_t> CameraConnection::command(
    Cmd command,
    std::span<const std::uint8_t> payload) {
    const auto frame = client_.make_command(info_.device_id, command, payload);
    transport_->send(frame);
    return transport_->receive();
}

void CameraConnection::close() noexcept { transport_->close(); }

ConnectionManager::ConnectionManager(
    std::array<std::uint8_t, key_len> key,
    TransportFactory factory,
    ConnectionOptions options)
    : key_(key), factory_(std::move(factory)), options_(std::move(options)) {
    if (!factory_) throw std::invalid_argument("transport factory is required");
}

std::vector<DeviceInfo> ConnectionManager::discover(DiscoveryProvider& provider) const {
    return provider.scan();
}

CameraConnection ConnectionManager::connect(const DeviceInfo& device) {
    for (const auto preferred : options_.preferred_transports) {
        const auto it = std::find(device.transports.begin(), device.transports.end(), preferred);
        if (it == device.transports.end()) continue;
        auto transport = factory_(device, preferred);
        if (transport && transport->connected()) {
            return CameraConnection(
                device,
                std::move(transport),
                CameraClient(key_));
        }
    }
    throw std::runtime_error("no compatible SyncStream transport available");
}

} // namespace syncstream
