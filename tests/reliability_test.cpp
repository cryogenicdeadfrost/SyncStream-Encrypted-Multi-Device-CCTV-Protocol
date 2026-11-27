#include "syncstream/reliability.hpp"

#include <cassert>
#include <chrono>
#include <iostream>

int main() {
    assert(syncstream::retry_class(syncstream::Cmd::get_status) == syncstream::RetryClass::safe);
    assert(syncstream::can_retry(syncstream::Cmd::start_recording));
    assert(!syncstream::can_retry(static_cast<syncstream::Cmd>(255)));

    syncstream::BackoffPolicy policy;
    policy.jitter_ratio = 0.0;
    const auto first = policy.delay_for(0);
    const auto second = policy.delay_for(1);
    assert(first == std::chrono::milliseconds(250));
    assert(second == std::chrono::milliseconds(500));

    syncstream::FaultMonitor monitor;
    monitor.state(syncstream::SessionState::connected);
    monitor.record_failure();
    monitor.record_failure();
    assert(monitor.consecutive_failures() == 2);
    monitor.record_success();
    assert(monitor.consecutive_failures() == 0);

    std::cout << "SYNCSTREAM RELIABILITY TEST: PASS\n";
}
