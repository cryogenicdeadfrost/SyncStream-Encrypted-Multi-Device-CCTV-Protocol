#include "syncstream/api.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {
constexpr std::uint16_t default_port = 39170;

std::uint32_t read_u32(int fd) {
    std::uint32_t value = 0;
    if (recv(fd, &value, sizeof(value), MSG_WAITALL) != sizeof(value)) {
        throw std::runtime_error("client disconnected while reading length");
    }
    return ntohl(value);
}

void write_frame(int fd, const std::vector<std::uint8_t>& frame) {
    const auto n = htonl(static_cast<std::uint32_t>(frame.size()));
    if (send(fd, &n, sizeof(n), MSG_NOSIGNAL) != sizeof(n) ||
        send(fd, frame.data(), frame.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(frame.size())) {
        throw std::runtime_error("client disconnected while writing");
    }
}

std::vector<std::uint8_t> read_frame(int fd) {
    const auto n = read_u32(fd);
    if (n == 0 || n > syncstream::max_payload_len + 128) {
        throw std::runtime_error("invalid frame size");
    }
    std::vector<std::uint8_t> frame(n);
    if (recv(fd, frame.data(), frame.size(), MSG_WAITALL) != static_cast<ssize_t>(frame.size())) {
        throw std::runtime_error("truncated frame");
    }
    return frame;
}

}

int main(int argc, char** argv) {
    try {
        const auto key_hex = argc > 1
            ? std::string(argv[1])
            : "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        const auto port = argc > 2
            ? static_cast<std::uint16_t>(std::stoul(argv[2]))
            : default_port;

        const auto key_bytes = syncstream::from_hex(key_hex);
        if (key_bytes.size() != syncstream::key_len) throw std::runtime_error("key must be 32 bytes");

        std::array<std::uint8_t, syncstream::key_len> key{};
        std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
        syncstream::CameraServer camera(key);

        const int server = socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) throw std::runtime_error("socket failed");

        int reuse = 1;
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(server);
            throw std::runtime_error("bind failed");
        }
        if (listen(server, 4) != 0) {
            close(server);
            throw std::runtime_error("listen failed");
        }

        std::cout << "SyncStream Android test bridge listening on TCP/" << port << '\n';

        while (true) {
            const int client = accept(server, nullptr, nullptr);
            if (client < 0) continue;

            try {
                while (true) {
                    const auto request_wire = read_frame(client);
                    const auto request = camera.open_wire(request_wire);
                    const auto response = camera.make_response(request, true, {});
                    write_frame(client, response);
                }
            } catch (const std::exception& ex) {
                std::cerr << "client session ended: " << ex.what() << '\n';
            }
            close(client);
        }
    } catch (const std::exception& ex) {
        std::cerr << "bridge error: " << ex.what() << '\n';
        return 2;
    }
}
