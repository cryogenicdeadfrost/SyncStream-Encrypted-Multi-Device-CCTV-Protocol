#include "syncstream/middleware.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace syncstream {
namespace {

[[noreturn]] void die(const std::string& msg) {
    throw std::runtime_error(msg);
}

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFU));
    }
}

std::uint16_t read_u16(std::span<const std::uint8_t> raw, std::size_t& at) {
    if (at + 2 > raw.size()) {
        die("u16 bounds");
    }
    const std::uint16_t v = static_cast<std::uint16_t>((static_cast<std::uint16_t>(raw[at]) << 8) | raw[at + 1]);
    at += 2;
    return v;
}

std::uint64_t read_u64(std::span<const std::uint8_t> raw, std::size_t& at) {
    if (at + 8 > raw.size()) {
        die("u64 bounds");
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = static_cast<std::uint64_t>((v << 8) | raw[at + static_cast<std::size_t>(i)]);
    }
    at += 8;
    return v;
}

std::string take_str(std::span<const std::uint8_t> raw, std::size_t& at) {
    const auto n = static_cast<std::size_t>(read_u16(raw, at));
    if (at + n > raw.size()) {
        die("str bounds");
    }
    std::string s(raw.begin() + static_cast<std::ptrdiff_t>(at), raw.begin() + static_cast<std::ptrdiff_t>(at + n));
    at += n;
    return s;
}

std::vector<std::uint8_t> take_vec(std::span<const std::uint8_t> raw, std::size_t& at) {
    const auto n = static_cast<std::size_t>(read_u16(raw, at));
    if (at + n > raw.size()) {
        die("vec bounds");
    }
    std::vector<std::uint8_t> v(raw.begin() + static_cast<std::ptrdiff_t>(at), raw.begin() + static_cast<std::ptrdiff_t>(at + n));
    at += n;
    return v;
}

}

std::uint64_t now_ms() {
    const auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    return static_cast<std::uint64_t>(now.time_since_epoch().count());
}

RelayCore::RelayCore(std::array<std::uint8_t, key_len> key, std::chrono::milliseconds max_skew, std::size_t replay_cap)
    : rig_(key), max_skew_(max_skew), replay_cap_(replay_cap) {
    if (replay_cap_ == 0) {
        die("replay cap cannot be zero");
    }
}

std::vector<std::uint8_t> RelayCore::aad_for(std::uint64_t seq, std::uint64_t at_ms) const {
    std::vector<std::uint8_t> out;
    out.reserve(16);
    put_u64(out, seq);
    put_u64(out, at_ms);
    return out;
}

std::vector<std::uint8_t> RelayCore::pack_ctrl(const Ctrl& ctrl) const {
    if (ctrl.dev.size() > std::numeric_limits<std::uint16_t>::max()) {
        die("device id too long");
    }
    if (ctrl.body.size() > std::numeric_limits<std::uint16_t>::max()) {
        die("payload too long");
    }
    std::vector<std::uint8_t> out;
    out.reserve(2 + ctrl.dev.size() + 1 + 8 + 2 + ctrl.body.size());
    put_u16(out, static_cast<std::uint16_t>(ctrl.dev.size()));
    out.insert(out.end(), ctrl.dev.begin(), ctrl.dev.end());
    out.push_back(static_cast<std::uint8_t>(ctrl.cmd));
    put_u64(out, ctrl.at_ms);
    put_u16(out, static_cast<std::uint16_t>(ctrl.body.size()));
    out.insert(out.end(), ctrl.body.begin(), ctrl.body.end());
    return out;
}

Ctrl RelayCore::unpack_ctrl(std::span<const std::uint8_t> raw) const {
    std::size_t at = 0;
    Ctrl ctrl{};
    ctrl.dev = take_str(raw, at);
    if (at >= raw.size()) {
        die("missing cmd");
    }
    ctrl.cmd = static_cast<Cmd>(raw[at]);
    at += 1;
    ctrl.at_ms = read_u64(raw, at);
    ctrl.body = take_vec(raw, at);
    if (at != raw.size()) {
        die("trailing bytes");
    }
    return ctrl;
}

bool RelayCore::seen_or_mark(const std::string& k) {
    auto [it, fresh] = seen_.insert(k);
    if (!fresh) {
        return true;
    }
    fifo_.push_back(*it);
    trim();
    return false;
}

void RelayCore::trim() {
    while (fifo_.size() > replay_cap_) {
        const auto& old = fifo_.front();
        seen_.erase(old);
        fifo_.pop_front();
    }
}

Env RelayCore::seal_ctrl(const Ctrl& ctrl) {
    std::scoped_lock lock(mu_);
    ++seq_;
    const auto aad = aad_for(seq_, ctrl.at_ms);
    const auto raw = pack_ctrl(ctrl);
    Env env{};
    env.seq = seq_;
    env.at_ms = ctrl.at_ms;
    env.pkt = rig_.seal(raw, aad);
    return env;
}

Ctrl RelayCore::open_ctrl(const Env& env) {
    const auto now = now_ms();
    const auto low = now >= static_cast<std::uint64_t>(max_skew_.count()) ? now - static_cast<std::uint64_t>(max_skew_.count()) : 0;
    const auto high = now + static_cast<std::uint64_t>(max_skew_.count());
    if (env.at_ms < low || env.at_ms > high) {
        die("timestamp skew");
    }

    {
        std::scoped_lock lock(mu_);
        const std::string key = std::to_string(env.seq) + ":" + hex_of(env.pkt.nonce) + ":" + hex_of(env.pkt.mac);
        if (seen_or_mark(key)) {
            die("replay blocked");
        }
    }

    const auto aad = aad_for(env.seq, env.at_ms);
    const auto plain = rig_.open(env.pkt, aad);
    return unpack_ctrl(plain.view());
}

}
