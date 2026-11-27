#pragma once

#include "syncstream/middleware.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>

namespace syncstream {

enum class RetryClass : std::uint8_t {
    never = 0,
    safe = 1,
    idempotent = 2
};

RetryClass retry_class(Cmd command);
bool can_retry(Cmd command);

enum class SessionState : std::uint8_t {
    disconnected,
    discovering,
    pairing,
    authenticating,
    connected,
    degraded,
    reconnecting,
    closed
};

struct BackoffPolicy {
    std::size_t max_attempts{5};
    std::chrono::milliseconds initial_delay{250};
    std::chrono::milliseconds max_delay{8000};
    double jitter_ratio{0.20};

    std::chrono::milliseconds delay_for(std::size_t attempt) const;
};

class FaultMonitor {
public:
    void state(SessionState state) noexcept;
    SessionState state() const noexcept;
    void record_success() noexcept;
    void record_failure() noexcept;
    std::size_t consecutive_failures() const noexcept;

private:
    SessionState state_{SessionState::disconnected};
    std::size_t failures_{0};
};

} // namespace syncstream
