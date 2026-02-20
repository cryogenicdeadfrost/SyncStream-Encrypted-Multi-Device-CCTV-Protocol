#include "syncstream/edge_hub.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace syncstream {
namespace {

[[noreturn]] void die(const std::string& msg) {
    throw std::runtime_error(msg);
}

}

RateGate::RateGate(std::size_t burst, std::size_t refill_per_sec) : burst_(burst), refill_(refill_per_sec) {
    if (burst_ == 0 || refill_ == 0) {
        die("rate gate config invalid");
    }
}

bool RateGate::hit(const std::string& dev, std::uint64_t now) {
    std::scoped_lock lock(mu_);
    auto& b = slots_[dev];
    if (b.last == 0) {
        b.tok = static_cast<double>(burst_);
        b.last = now;
    }
    const std::uint64_t dt = now >= b.last ? now - b.last : 0;
    const double fill = static_cast<double>(dt) / 1000.0 * static_cast<double>(refill_);
    b.tok = std::min(static_cast<double>(burst_), b.tok + fill);
    b.last = now;
    if (b.tok < 1.0) {
        return false;
    }
    b.tok -= 1.0;
    return true;
}

void PolicyGate::allow(Cmd cmd) {
    allow_.insert(static_cast<std::uint8_t>(cmd));
}

bool PolicyGate::can(Cmd cmd) const {
    return allow_.find(static_cast<std::uint8_t>(cmd)) != allow_.end();
}

EdgeHub::EdgeHub(std::array<std::uint8_t, key_len> master, std::chrono::milliseconds max_skew, std::size_t replay_cap, std::size_t burst, std::size_t refill_per_sec)
    : keychain_(master), max_skew_(max_skew), replay_cap_(replay_cap), rate_(burst, refill_per_sec) {}

void EdgeHub::stage_key(std::uint32_t ver, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ctx, bool activate_now) {
    keychain_.stage(ver, salt, ctx);
    if (activate_now) {
        keychain_.activate(ver);
    }
}

void EdgeHub::allow_cmd(Cmd cmd) {
    policy_.allow(cmd);
}

RelayCore& EdgeHub::core_for(std::uint32_t ver) {
    std::scoped_lock lock(mu_);
    auto it = cores_.find(ver);
    if (it != cores_.end()) {
        return *(it->second);
    }
    const auto key = keychain_.take(ver);
    auto core = std::make_unique<RelayCore>(key, max_skew_, replay_cap_);
    auto [pos, ok] = cores_.emplace(ver, std::move(core));
    if (!ok) {
        die("core map insert failed");
    }
    return *(pos->second);
}

VersionedEnv EdgeHub::seal(const Ctrl& ctrl) {
    if (!policy_.can(ctrl.cmd)) {
        die("cmd not allowed");
    }
    const auto now = now_ms();
    if (!rate_.hit(ctrl.dev, now)) {
        die("rate limited");
    }
    const auto ver = keychain_.active();
    auto& core = core_for(ver);
    return VersionedEnv{ver, core.seal_ctrl(ctrl)};
}

Ctrl EdgeHub::open(const VersionedEnv& env) {
    auto& core = core_for(env.key_ver);
    const auto ctrl = core.open_ctrl(env.env);
    if (!policy_.can(ctrl.cmd)) {
        die("cmd not allowed");
    }
    const auto now = now_ms();
    if (!rate_.hit(ctrl.dev, now)) {
        die("rate limited");
    }
    return ctrl;
}

}
