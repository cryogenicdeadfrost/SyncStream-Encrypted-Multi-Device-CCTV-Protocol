#pragma once

#include "syncstream/secure_channel.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace syncstream {

enum class Cmd : std::uint8_t {
    arm = 1,
    disarm = 2,
    sync = 3,
    ping = 4
};

struct Ctrl {
    std::string dev;
    Cmd cmd;
    std::uint64_t at_ms;
    std::vector<std::uint8_t> body;
};

struct Env {
    std::uint64_t seq;
    std::uint64_t at_ms;
    Packet pkt;
};

class RelayCore {
public:
    RelayCore(std::array<std::uint8_t, key_len> key, std::chrono::milliseconds max_skew, std::size_t replay_cap = 8192);

    Env seal_ctrl(const Ctrl& ctrl);
    Ctrl open_ctrl(const Env& env);

private:
    std::vector<std::uint8_t> pack_ctrl(const Ctrl& ctrl) const;
    Ctrl unpack_ctrl(std::span<const std::uint8_t> raw) const;
    std::vector<std::uint8_t> aad_for(std::uint64_t seq, std::uint64_t at_ms) const;

    bool seen_or_mark(const std::string& k);
    void trim();

    CipherRig rig_;
    std::chrono::milliseconds max_skew_;
    std::size_t replay_cap_;
    std::uint64_t seq_ = 0;
    std::unordered_set<std::string> seen_;
    std::deque<std::string> fifo_;
    std::mutex mu_;
};

std::uint64_t now_ms();

}
