#include "syncstream/edge_hub.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void need(bool ok, const std::string& msg) {
    if (!ok) {
        throw std::runtime_error(msg);
    }
}

void rotate_and_open() {
    const auto master = syncstream::mint_key();
    syncstream::EdgeHub tx(master, std::chrono::seconds(30), 2048, 200, 200);
    syncstream::EdgeHub rx(master, std::chrono::seconds(30), 2048, 200, 200);

    std::vector<std::uint8_t> s1{1, 2, 3};
    std::vector<std::uint8_t> c1{'z', '1'};
    tx.stage_key(1, s1, c1, true);
    rx.stage_key(1, s1, c1, true);

    tx.allow_cmd(syncstream::Cmd::sync);
    rx.allow_cmd(syncstream::Cmd::sync);

    syncstream::Ctrl ctrl{"cam-a", syncstream::Cmd::sync, syncstream::now_ms(), {7, 7, 7}};
    const auto env1 = tx.seal(ctrl);
    const auto out1 = rx.open(env1);
    need(out1.dev == ctrl.dev, "first open failed");

    std::vector<std::uint8_t> s2{4, 5, 6};
    std::vector<std::uint8_t> c2{'z', '2'};
    tx.stage_key(2, s2, c2, true);
    rx.stage_key(2, s2, c2, true);

    ctrl.at_ms = syncstream::now_ms();
    ctrl.body = {9, 9, 9};
    const auto env2 = tx.seal(ctrl);
    need(env2.key_ver == 2, "rotation not active");
    const auto out2 = rx.open(env2);
    need(out2.body == ctrl.body, "second open failed");
}

void policy_block() {
    const auto master = syncstream::mint_key();
    syncstream::EdgeHub tx(master, std::chrono::seconds(30), 2048, 200, 200);
    std::vector<std::uint8_t> s{1};
    std::vector<std::uint8_t> c{2};
    tx.stage_key(1, s, c, true);

    syncstream::Ctrl ctrl{"cam-z", syncstream::Cmd::arm, syncstream::now_ms(), {1}};
    bool hit = false;
    try {
        static_cast<void>(tx.seal(ctrl));
    } catch (...) {
        hit = true;
    }
    need(hit, "policy not enforced");
}

void rate_block() {
    const auto master = syncstream::mint_key();
    syncstream::EdgeHub tx(master, std::chrono::seconds(30), 2048, 1, 1);
    std::vector<std::uint8_t> s{1};
    std::vector<std::uint8_t> c{2};
    tx.stage_key(1, s, c, true);
    tx.allow_cmd(syncstream::Cmd::sync);

    syncstream::Ctrl ctrl{"cam-rate", syncstream::Cmd::sync, syncstream::now_ms(), {1}};
    static_cast<void>(tx.seal(ctrl));

    ctrl.at_ms = syncstream::now_ms();
    bool hit = false;
    try {
        static_cast<void>(tx.seal(ctrl));
    } catch (...) {
        hit = true;
    }
    need(hit, "rate limit not enforced");
}

}

int main() {
    try {
        rotate_and_open();
        policy_block();
        rate_block();
        std::cout << "edge hub tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
