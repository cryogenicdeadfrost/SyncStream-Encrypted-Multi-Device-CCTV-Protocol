#pragma once

#include "syncstream/api.hpp"
#include "syncstream/bootstrap.hpp"
#include "syncstream/discovery.hpp"
#include "syncstream/transport.hpp"

#include <functional>
#include <memory>
#include <vector>

namespace syncstream {

struct ConnectionOptions {
    bool auto_pair{false};
    bool require_confirmation{true};
    std::vector<TransportKind> preferred_transports{
        TransportKind::wifi_direct,
        TransportKind::lan,
        TransportKind::ble,
        TransportKind::usb
    };
};

class CameraConnection {
public:
    CameraConnection(
        DeviceInfo info,
        std::unique_ptr<Transport> transport,
        std::unique_ptr<CameraClient> client);

    const DeviceInfo& info() const noexcept;
    TransportKind transport_kind() const noexcept;
    bool connected() const noexcept;

    std::vector<std::uint8_t> command(
        Cmd command,
        std::span<const std::uint8_t> payload = {});

    void close() noexcept;

private:
    DeviceInfo info_;
    std::unique_ptr<Transport> transport_;
    std::unique_ptr<CameraClient> client_;
};

class ConnectionManager {
public:
    using TransportFactory = std::function<std::unique_ptr<Transport>(
        const DeviceInfo&, TransportKind)>;

    ConnectionManager(
        std::array<std::uint8_t, key_len> key,
        TransportFactory factory,
        ConnectionOptions options = {});

    std::vector<DeviceInfo> discover(DiscoveryProvider& provider) const;
    CameraConnection connect(const DeviceInfo& device);

private:
    std::array<std::uint8_t, key_len> key_;
    TransportFactory factory_;
    ConnectionOptions options_;
};

} // namespace syncstream
