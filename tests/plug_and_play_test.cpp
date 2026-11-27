#include "syncstream/syncstream.hpp"

#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

namespace {

class LoopbackTransport final : public syncstream::Transport {
public:
    explicit LoopbackTransport(std::array<std::uint8_t, syncstream::key_len> key)
        : server_(key) {}

    syncstream::TransportInfo info() const override {
        return {syncstream::TransportKind::lan, "loopback", 65535, true, false};
    }

    void send(std::span<const std::uint8_t> frame) override {
        const auto request = server_.open_wire(frame);
        reply_ = server_.make_response(request, true, std::span<const std::uint8_t>{});
    }

    std::vector<std::uint8_t> receive() override { return reply_; }
    bool connected() const override { return true; }
    void close() noexcept override {}

private:
    syncstream::CameraServer server_;
    std::vector<std::uint8_t> reply_;
};

}

int main() {
    const auto key = syncstream::mint_key();

    syncstream::DeviceInfo device;
    device.device_id = "SS-TEST-001";
    device.name = "SyncStream Virtual Camera";
    device.type = syncstream::DeviceType::camera;
    device.capabilities = {
        syncstream::Capability::status,
        syncstream::Capability::recording
    };
    device.transports = {syncstream::TransportKind::lan};

    syncstream::StaticDiscovery discovery({device});
    syncstream::ConnectionManager manager(
        key,
        [key](const syncstream::DeviceInfo&, syncstream::TransportKind) {
            return std::make_unique<LoopbackTransport>(key);
        });

    const auto found = manager.discover(discovery);
    assert(found.size() == 1);
    auto connection = manager.connect(found.front());
    assert(connection.connected());

    const auto wire = connection.command(syncstream::Cmd::ping);
    syncstream::CameraClient verifier(key);
    const auto response = verifier.open_response(wire);
    assert(response.accepted);
    assert(!response.request_id.empty());

    const std::vector<std::uint8_t> identity{1, 2, 3, 4};
    assert(syncstream::Bootstrap::fingerprint(identity).size() == 64);

    std::cout << "SYNCSTREAM PLUG-AND-PLAY TEST: PASS\n";
}
