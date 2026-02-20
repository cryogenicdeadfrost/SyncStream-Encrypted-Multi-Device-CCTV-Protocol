#pragma once

#include "syncstream/keychain.hpp"
#include "syncstream/middleware.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace syncstream {

struct VersionedEnv {
    std::uint32_t key_ver;
    Env env;
};

class RateGate {
public:
    RateGate(std::size_t burst, std::size_t refill_per_sec);
    bool hit(const std::string& dev, std::uint64_t now);

private:
    struct Bucket {
        double tok;
        std::uint64_t last;
    };

    std::size_t burst_;
    std::size_t refill_;
    std::unordered_map<std::string, Bucket> slots_;
    std::mutex mu_;
};

class PolicyGate {
public:
    void allow(Cmd cmd);
    bool can(Cmd cmd) const;

private:
    std::unordered_set<std::uint8_t> allow_;
};

class EdgeHub {
public:
    EdgeHub(std::array<std::uint8_t, key_len> master, std::chrono::milliseconds max_skew, std::size_t replay_cap, std::size_t burst, std::size_t refill_per_sec);

    void stage_key(std::uint32_t ver, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ctx, bool activate_now);
    void allow_cmd(Cmd cmd);

    VersionedEnv seal(const Ctrl& ctrl);
    Ctrl open(const VersionedEnv& env);

private:
    RelayCore& core_for(std::uint32_t ver);

    Keychain keychain_;
    std::chrono::milliseconds max_skew_;
    std::size_t replay_cap_;
    RateGate rate_;
    PolicyGate policy_;
    std::unordered_map<std::uint32_t, std::unique_ptr<RelayCore>> cores_;
    std::mutex mu_;
};

}
