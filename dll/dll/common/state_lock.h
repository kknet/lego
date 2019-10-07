#pragma once

#include <mutex>
#include <condition_variable>

#include "common/utils.h"

namespace lego {

namespace common {

class StateLock {
public:
    explicit StateLock(int32_t cnt);
    void Wait();
    void Signal();
    bool WaitFor(int64_t wait_us);

private:
    std::mutex mutex_;
    std::condition_variable con_;
    int32_t count_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(StateLock);
};

}  // namespace common

}  // namespace lego
