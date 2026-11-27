#include "syncstream/reliability.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace syncstream {

RetryClass retry_class(Cmd command) {
    switch (command) {
        case Cmd::ping:
        case Cmd::get_status:
        case Cmd::sync:
            return RetryClass::safe;
        case Cmd::arm:
        case Cmd::disarm:
        case Cmd::set_stream:
        case Cmd::start_recording:
        case Cmd::stop_recording:
        case Cmd::ptz:
            return RetryClass::idempotent;
    }
    return RetryClass::never;
}

bool can_retry(Cmd command) {
    return retry_class(command) != RetryClass::never;
}

std::chrono::milliseconds BackoffPolicy::delay_for(std::size_t attempt) const {
    if (max_attempts == 0 || initial_delay.count() < 0 || max_delay.count() < 0 ||
        initial_delay > max_delay || jitter_ratio < 0.0 || jitter_ratio > 1.0) {
        throw std::invalid_argument("invalid backoff policy");
    }

    const auto exponent = std::min<std::size_t>(attempt, 30);
    const auto multiplier = static_cast<std::uint64_t>(1ULL << exponent);
    const auto raw = std::min(
        static_cast<std::uint64_t>(max_delay.count()),
        static_cast<std::uint64_t>(initial_delay.count()) * multiplier);

    if (jitter_ratio == 0.0 || raw == 0) {
        return std::chrono::milliseconds(static_cast<std::int64_t>(raw));
    }

    std::random_device rd;
    std::mt19937_64 rng((static_cast<std::uint64_t>(rd()) << 32U) ^ rd());
    const auto spread = static_cast<std::uint64_t>(
        std::llround(static_cast<double>(raw) * jitter_ratio));
    std::uniform_int_distribution<std::int64_t> distribution(
        -static_cast<std::int64_t>(spread),
        static_cast<std::int64_t>(spread));

    const auto jittered = std::max<std::int64_t>(
        0,
        static_cast<std::int64_t>(raw) + distribution(rng));
    return std::chrono::milliseconds(jittered);
}

void FaultMonitor::state(SessionState state) noexcept { state_ = state; }

SessionState FaultMonitor::state() const noexcept { return state_; }

void FaultMonitor::record_success() noexcept { failures_ = 0; }

void FaultMonitor::record_failure() noexcept { ++failures_; }

std::size_t FaultMonitor::consecutive_failures() const noexcept { return failures_; }

} // namespace syncstream
