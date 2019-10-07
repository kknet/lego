#include "stdafx.h"
#include "common/state_lock.h"

namespace lego {

namespace common {

StateLock::StateLock(int32_t cnt) : count_(cnt) {}

void StateLock::Wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (count_ > 0) {
        --count_;
        return;
    }

    con_.wait(lock, [this] { return count_ > 0; });
    count_ -= 1;
}

void StateLock::Signal() {
    std::unique_lock<std::mutex> lock(mutex_);
    ++count_;
    if (count_ > 0) {
        con_.notify_one();
    }
}

bool StateLock::WaitFor(int64_t wait_us) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (count_ > 0) {
        --count_;
        return true;
    }

    bool waited = con_.wait_for(
            lock,
            std::chrono::microseconds(wait_us),
            [this] { return count_ > 0; });
    if (!waited) {
        return false;
    }

    --count_;
    return true;
}

}  // namespace common

}  // namespace lego
