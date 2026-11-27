#include <jni.h>
#include <android/log.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "syncstream/api.hpp"
#include "syncstream/secure_channel.hpp"

namespace {
std::mutex mu;
int fd = -1;
std::unique_ptr<syncstream::CameraClient> client;

std::string jstr(JNIEnv* env, jstring value) {
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string out(chars ? chars : "");
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return out;
}

std::vector<std::uint8_t> hex_key(const std::string& text) {
    return syncstream::from_hex(text);
}

std::string exchange(std::span<const std::uint8_t> frame) {
    if (fd < 0) throw std::runtime_error("not connected");

    const std::uint32_t n = htonl(static_cast<std::uint32_t>(frame.size()));
    if (send(fd, &n, sizeof(n), MSG_NOSIGNAL) != sizeof(n) ||
        send(fd, frame.data(), frame.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(frame.size())) {
        throw std::runtime_error("send failed");
    }

    std::uint32_t wire_n = 0;
    if (recv(fd, &wire_n, sizeof(wire_n), MSG_WAITALL) != sizeof(wire_n)) {
        throw std::runtime_error("bridge closed");
    }

    wire_n = ntohl(wire_n);
    if (wire_n == 0 || wire_n > syncstream::max_payload_len + 128) {
        throw std::runtime_error("invalid bridge frame size");
    }

    std::vector<std::uint8_t> reply(wire_n);
    if (recv(fd, reply.data(), reply.size(), MSG_WAITALL) != static_cast<ssize_t>(reply.size())) {
        throw std::runtime_error("truncated bridge reply");
    }
    return syncstream::hex_of(reply);
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_syncstream_test_MainActivity_nativeConnect(
    JNIEnv* env, jobject, jstring host, jint port, jstring keyHex) {
    std::lock_guard lock(mu);
    try {
        const auto key = syncstream::from_hex(jstr(env, keyHex));
        if (key.size() != syncstream::key_len) throw std::runtime_error("key must be 32 bytes");

        if (fd >= 0) close(fd);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw std::runtime_error("socket failed");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<std::uint16_t>(port));
        if (inet_pton(AF_INET, jstr(env, host).c_str(), &addr.sin_addr) != 1) {
            throw std::runtime_error("invalid IPv4 address");
        }

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(fd);
            fd = -1;
            throw std::runtime_error(std::string("connect failed: ") + std::strerror(errno));
        }

        std::array<std::uint8_t, syncstream::key_len> key_array{};
        std::copy(key.begin(), key.end(), key_array.begin());
        client = std::make_unique<syncstream::CameraClient>(key_array);

        return env->NewStringUTF("Connected to SyncStream bridge");
    } catch (const std::exception& e) {
        return env->NewStringUTF(e.what());
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_syncstream_test_MainActivity_nativeCommand(
    JNIEnv* env, jobject, jint command) {
    std::lock_guard lock(mu);
    try {
        if (!client) throw std::runtime_error("not connected");

        const auto frame = client->make_command(
            "SS-TEST-001",
            static_cast<syncstream::Cmd>(command));

        const auto reply_hex = exchange(frame);
        const auto reply = syncstream::from_hex(reply_hex);
        const auto response = client->open_response(reply);

        const std::string result =
            response.accepted ? "SyncStream command accepted" :
            "SyncStream command rejected: " + response.error;
        return env->NewStringUTF(result.c_str());
    } catch (const std::exception& e) {
        return env->NewStringUTF(e.what());
    }
}
