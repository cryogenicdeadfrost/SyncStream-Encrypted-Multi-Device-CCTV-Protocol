#include "syncstream/middleware.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void need(bool ok, const std::string& msg) {
    if (!ok) {
        throw std::runtime_error(msg);
    }
}

void flow_ok() {
    const auto key = syncstream::mint_key();
    syncstream::RelayCore tx(key, std::chrono::seconds(30));
    syncstream::RelayCore rx(key, std::chrono::seconds(30));

    syncstream::Ctrl c{};
    c.dev = "pixel-7";
    c.cmd = syncstream::Cmd::sync;
    c.at_ms = syncstream::now_ms();
    c.body = {1, 2, 3, 4};

    const auto env = tx.seal_ctrl(c);
    const auto out = rx.open_ctrl(env);
    need(out.dev == c.dev, "dev mismatch");
    need(out.cmd == c.cmd, "cmd mismatch");
    need(out.body == c.body, "body mismatch");
}

void replay_blocked() {
    const auto key = syncstream::mint_key();
    syncstream::RelayCore tx(key, std::chrono::seconds(30));
    syncstream::RelayCore rx(key, std::chrono::seconds(30));

    syncstream::Ctrl c{"moto-edge", syncstream::Cmd::arm, syncstream::now_ms(), {9, 8}};
    const auto env = tx.seal_ctrl(c);
    static_cast<void>(rx.open_ctrl(env));

    bool hit = false;
    try {
        static_cast<void>(rx.open_ctrl(env));
    } catch (...) {
        hit = true;
    }
    need(hit, "replay not blocked");
}

void skew_blocked() {
    const auto key = syncstream::mint_key();
    syncstream::RelayCore tx(key, std::chrono::seconds(30));
    syncstream::RelayCore rx(key, std::chrono::milliseconds(1));

    syncstream::Ctrl c{"galaxy-s24", syncstream::Cmd::ping, syncstream::now_ms() - 1000, {7}};
    const auto env = tx.seal_ctrl(c);

    bool hit = false;
    try {
        static_cast<void>(rx.open_ctrl(env));
    } catch (...) {
        hit = true;
    }
    need(hit, "skew not blocked");
}

}

int main() {
    try {
        flow_ok();
        replay_blocked();
        skew_blocked();
        std::cout << "middleware tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
