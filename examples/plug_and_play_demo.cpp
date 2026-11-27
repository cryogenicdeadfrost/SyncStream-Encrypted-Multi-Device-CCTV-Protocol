#include <syncstream/syncstream.hpp>

#include <iostream>
#include <memory>

namespace {

class DemoTransport final : public syncstream::Transport {
public:
    explicit DemoTransport(std::array<std::uint8_t, syncstream::key_len> key)
        : server_(key) {}

    syncstream::TransportInfo info() const override {
        return {syncstream::TransportKind::lan, "demo-loopback", 65535, true, false};
    }

    void send(std::span<const std::uint8_t> frame) override {
        const auto request = server_.open_wire(frame);
        reply_ = server_.make_response(request, true, {});
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

    syncstream::DeviceInfo camera;
    camera.device_id = "SS-TEST-001";
    camera.name = "Developer Test Camera";
    camera.type = syncstream::DeviceType::camera;
    camera.capabilities = {
        syncstream::Capability::status,
        syncstream::Capability::recording
    };
    camera.transports = {syncstream::TransportKind::lan};

    syncstream::StaticDiscovery discovery({camera});
    syncstream::ConnectionManager phone(
        key,
        [key](const syncstream::DeviceInfo&, syncstream::TransportKind) {
            return std::make_unique<DemoTransport>(key);
        });

    const auto devices = phone.discover(discovery);
    if (devices.empty()) return 1;

    auto connected = phone.connect(devices.front());
    const auto wire = connected.command(syncstream::Cmd::get_status);

    syncstream::CameraClient verifier(key);
    const auto response = verifier.open_response(wire);

    std::cout << "Connected to " << connected.info().name
              << " over " << syncstream::transport_name(connected.transport_kind())
              << ": " << (response.accepted ? "OK" : "REJECTED") << '\n';
    return response.accepted ? 0 : 1;
}
