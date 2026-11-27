#pragma once

#include "syncstream/edge_hub.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace syncstream {

inline constexpr std::uint8_t wire_version = 1;
inline constexpr std::size_t max_device_id_len = 255;
inline constexpr std::size_t max_payload_len = 65535;

struct ApiConfig {
    std::chrono::milliseconds max_skew{std::chrono::seconds(30)};
    std::size_t replay_cap{8192};
    std::size_t max_payload{4096};

    static ApiConfig phone_camera();
    static ApiConfig edge_relay();
};

struct CommandRequest {
    std::string request_id;
    std::string device_id;
    Cmd command{Cmd::ping};
    std::vector<std::uint8_t> payload;
    std::uint64_t issued_at_ms{0};
};

struct CommandResponse {
    std::string request_id;
    std::string device_id;
    bool accepted{false};
    std::vector<std::uint8_t> payload;
    std::string error;
};

class WireCodec {
public:
    static std::vector<std::uint8_t> encode(const Env& env);
    static Env decode(std::span<const std::uint8_t> wire);
    static std::vector<std::uint8_t> encode(const VersionedEnv& env);
    static VersionedEnv decode_versioned(std::span<const std::uint8_t> wire);
};

class CameraClient {
public:
    CameraClient(std::array<std::uint8_t, key_len> key, ApiConfig config = ApiConfig::phone_camera());

    std::vector<std::uint8_t> make_command(
        std::string_view device_id,
        Cmd command,
        std::span<const std::uint8_t> payload = {});

    CommandRequest make_request(
        std::string_view device_id,
        Cmd command,
        std::span<const std::uint8_t> payload = {});

    Env seal(const CommandRequest& request);
    std::vector<std::uint8_t> seal_wire(const CommandRequest& request);
    CommandResponse open_response(std::span<const std::uint8_t> wire);

private:
    RelayCore core_;
    ApiConfig config_;
};

class CameraServer {
public:
    CameraServer(std::array<std::uint8_t, key_len> key, ApiConfig config = ApiConfig::edge_relay());

    CommandRequest open(const Env& env);
    CommandRequest open_wire(std::span<const std::uint8_t> wire);

    std::vector<std::uint8_t> make_response(
        const CommandRequest& request,
        bool accepted,
        std::span<const std::uint8_t> payload = {},
        std::string_view error = {});

private:
    RelayCore core_;
    ApiConfig config_;
};

std::string new_request_id();

} // namespace syncstream
