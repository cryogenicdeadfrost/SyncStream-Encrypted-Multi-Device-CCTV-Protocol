#include "syncstream/api.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace syncstream {
namespace {

[[noreturn]] void fail(const char* message) { throw std::runtime_error(message); }

void put_u8(std::vector<std::uint8_t>& out, std::uint8_t v) { out.push_back(v); }

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

void put_bytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> data) {
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) fail("wire field too large");
    put_u32(out, static_cast<std::uint32_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
}

std::uint8_t get_u8(std::span<const std::uint8_t> in, std::size_t& at) {
    if (at >= in.size()) fail("truncated wire message");
    return in[at++];
}

std::uint16_t get_u16(std::span<const std::uint8_t> in, std::size_t& at) {
    if (at + 2 > in.size()) fail("truncated wire message");
    const auto v = static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[at]) << 8) | in[at + 1]);
    at += 2;
    return v;
}

std::uint32_t get_u32(std::span<const std::uint8_t> in, std::size_t& at) {
    if (at + 4 > in.size()) fail("truncated wire message");
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = static_cast<std::uint32_t>((v << 8) | in[at + static_cast<std::size_t>(i)]);
    at += 4;
    return v;
}

std::uint64_t get_u64(std::span<const std::uint8_t> in, std::size_t& at) {
    if (at + 8 > in.size()) fail("truncated wire message");
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = static_cast<std::uint64_t>((v << 8) | in[at + static_cast<std::size_t>(i)]);
    at += 8;
    return v;
}

std::vector<std::uint8_t> get_bytes(std::span<const std::uint8_t> in, std::size_t& at, std::size_t limit) {
    const auto n = static_cast<std::size_t>(get_u32(in, at));
    if (n > limit || at + n > in.size()) fail("wire field too large or truncated");
    std::vector<std::uint8_t> out(in.begin() + static_cast<std::ptrdiff_t>(at),
                                  in.begin() + static_cast<std::ptrdiff_t>(at + n));
    at += n;
    return out;
}

void validate_config(const ApiConfig& config) {
    if (config.max_skew.count() < 0) fail("max skew cannot be negative");
    if (config.replay_cap == 0) fail("replay cap cannot be zero");
    if (config.max_payload == 0 || config.max_payload > max_payload_len) fail("invalid maximum payload");
}

void validate_request(const CommandRequest& request, const ApiConfig& config) {
    if (request.request_id.empty() || request.request_id.size() > 128) fail("request id invalid");
    if (request.device_id.empty() || request.device_id.size() > max_device_id_len) fail("device id invalid");
    if (request.payload.size() > config.max_payload) fail("payload exceeds configured limit");
}

std::vector<std::uint8_t> pack_request(const CommandRequest& request) {
    if (request.request_id.size() > std::numeric_limits<std::uint16_t>::max()) fail("request id too long");
    std::vector<std::uint8_t> out;
    put_u16(out, static_cast<std::uint16_t>(request.request_id.size()));
    out.insert(out.end(), request.request_id.begin(), request.request_id.end());
    out.insert(out.end(), request.payload.begin(), request.payload.end());
    return out;
}

CommandRequest unpack_request(const Ctrl& ctrl, const ApiConfig& config) {
    std::size_t at = 0;
    const auto id_len = static_cast<std::size_t>(get_u16(ctrl.body, at));
    if (id_len == 0 || id_len > 128 || at + id_len > ctrl.body.size()) fail("invalid request id");

    CommandRequest request;
    request.request_id.assign(ctrl.body.begin() + static_cast<std::ptrdiff_t>(at),
                              ctrl.body.begin() + static_cast<std::ptrdiff_t>(at + id_len));
    at += id_len;
    request.device_id = ctrl.dev;
    request.command = ctrl.cmd;
    request.issued_at_ms = ctrl.at_ms;
    request.payload.assign(ctrl.body.begin() + static_cast<std::ptrdiff_t>(at), ctrl.body.end());
    validate_request(request, config);
    return request;
}

std::vector<std::uint8_t> pack_response(const CommandResponse& response, std::size_t max_payload) {
    if (response.request_id.empty() || response.request_id.size() > std::numeric_limits<std::uint16_t>::max()) fail("invalid response request id");
    if (response.payload.size() > max_payload) fail("response payload exceeds configured limit");
    if (response.error.size() > 1024) fail("response error too long");

    std::vector<std::uint8_t> out;
    put_u16(out, static_cast<std::uint16_t>(response.request_id.size()));
    out.insert(out.end(), response.request_id.begin(), response.request_id.end());
    put_u8(out, response.accepted ? 1U : 0U);
    put_bytes(out, response.payload);
    put_u16(out, static_cast<std::uint16_t>(response.error.size()));
    out.insert(out.end(), response.error.begin(), response.error.end());
    return out;
}

CommandResponse unpack_response(const Ctrl& ctrl) {
    std::size_t at = 0;
    const auto id_len = static_cast<std::size_t>(get_u16(ctrl.body, at));
    if (id_len == 0 || id_len > 128 || at + id_len > ctrl.body.size()) fail("invalid response request id");

    CommandResponse response;
    response.request_id.assign(ctrl.body.begin() + static_cast<std::ptrdiff_t>(at),
                               ctrl.body.begin() + static_cast<std::ptrdiff_t>(at + id_len));
    at += id_len;
    response.device_id = ctrl.dev;
    response.accepted = get_u8(ctrl.body, at) != 0;
    response.payload = get_bytes(ctrl.body, at, max_payload_len);

    const auto error_len = static_cast<std::size_t>(get_u16(ctrl.body, at));
    if (error_len > 1024 || at + error_len != ctrl.body.size()) fail("invalid response error");
    response.error.assign(ctrl.body.begin() + static_cast<std::ptrdiff_t>(at), ctrl.body.end());
    return response;
}

} // namespace

ApiConfig ApiConfig::phone_camera() { return {}; }
ApiConfig ApiConfig::edge_relay() { return {}; }

std::vector<std::uint8_t> WireCodec::encode(const Env& env) {
    if (env.pkt.body.size() > max_payload_len) fail("ciphertext exceeds wire limit");

    std::vector<std::uint8_t> out;
    out.reserve(1 + 8 + 8 + nonce_len + 4 + env.pkt.body.size() + tag_len);
    put_u8(out, wire_version);
    put_u64(out, env.seq);
    put_u64(out, env.at_ms);
    out.insert(out.end(), env.pkt.nonce.begin(), env.pkt.nonce.end());
    put_bytes(out, env.pkt.body);
    out.insert(out.end(), env.pkt.mac.begin(), env.pkt.mac.end());
    return out;
}

Env WireCodec::decode(std::span<const std::uint8_t> wire) {
    std::size_t at = 0;
    if (get_u8(wire, at) != wire_version) fail("unsupported wire version");

    Env env{};
    env.seq = get_u64(wire, at);
    env.at_ms = get_u64(wire, at);

    if (at + nonce_len > wire.size()) fail("truncated nonce");
    std::copy_n(wire.begin() + static_cast<std::ptrdiff_t>(at), nonce_len, env.pkt.nonce.begin());
    at += nonce_len;

    env.pkt.body = get_bytes(wire, at, max_payload_len);
    if (at + tag_len != wire.size()) fail("invalid authentication tag length");
    std::copy_n(wire.begin() + static_cast<std::ptrdiff_t>(at), tag_len, env.pkt.mac.begin());
    return env;
}

std::vector<std::uint8_t> WireCodec::encode(const VersionedEnv& env) {
    const auto inner = encode(env.env);
    std::vector<std::uint8_t> out;
    out.reserve(1 + 4 + inner.size());
    put_u8(out, wire_version);
    put_u32(out, env.key_ver);
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

VersionedEnv WireCodec::decode_versioned(std::span<const std::uint8_t> wire) {
    if (wire.size() < 5) fail("truncated versioned envelope");

    std::size_t at = 0;
    if (get_u8(wire, at) != wire_version) fail("unsupported wire version");

    VersionedEnv env{};
    env.key_ver = get_u32(wire, at);
    env.env = decode(wire.subspan(at));
    return env;
}

CameraClient::CameraClient(std::array<std::uint8_t, key_len> key, ApiConfig config)
    : core_(key, config.max_skew, config.replay_cap), config_(config) {
    validate_config(config_);
}

CommandRequest CameraClient::make_request(
    std::string_view device_id,
    Cmd command,
    std::span<const std::uint8_t> payload) {
    CommandRequest request;
    request.request_id = new_request_id();
    request.device_id = std::string(device_id);
    request.command = command;
    request.payload.assign(payload.begin(), payload.end());
    request.issued_at_ms = now_ms();
    validate_request(request, config_);
    return request;
}

std::vector<std::uint8_t> CameraClient::make_command(
    std::string_view device_id,
    Cmd command,
    std::span<const std::uint8_t> payload) {
    return seal_wire(make_request(device_id, command, payload));
}

Env CameraClient::seal(const CommandRequest& request) {
    validate_request(request, config_);
    Ctrl ctrl{request.device_id, request.command, request.issued_at_ms, pack_request(request)};
    return core_.seal_ctrl(ctrl);
}

std::vector<std::uint8_t> CameraClient::seal_wire(const CommandRequest& request) {
    return WireCodec::encode(seal(request));
}

CommandResponse CameraClient::open_response(std::span<const std::uint8_t> wire) {
    const auto ctrl = core_.open_ctrl(WireCodec::decode(wire));
    if (ctrl.cmd != Cmd::ping) fail("unexpected response command");
    return unpack_response(ctrl);
}

CameraServer::CameraServer(std::array<std::uint8_t, key_len> key, ApiConfig config)
    : core_(key, config.max_skew, config.replay_cap), config_(config) {
    validate_config(config_);
}

CommandRequest CameraServer::open(const Env& env) {
    return unpack_request(core_.open_ctrl(env), config_);
}

CommandRequest CameraServer::open_wire(std::span<const std::uint8_t> wire) {
    return open(WireCodec::decode(wire));
}

std::vector<std::uint8_t> CameraServer::make_response(
    const CommandRequest& request,
    bool accepted,
    std::span<const std::uint8_t> payload,
    std::string_view error) {
    CommandResponse response{
        request.request_id,
        request.device_id,
        accepted,
        std::vector<std::uint8_t>(payload.begin(), payload.end()),
        std::string(error)};
    const auto body = pack_response(response, config_.max_payload);
    Ctrl ctrl{request.device_id, Cmd::ping, now_ms(), body};
    return WireCodec::encode(core_.seal_ctrl(ctrl));
}

std::string new_request_id() {
    std::array<std::uint8_t, 16> raw{};
    const auto key = mint_key();
    std::copy_n(key.begin(), raw.size(), raw.begin());
    return hex_of(raw);
}

} // namespace syncstream
