#pragma once

#include <functional>
#include <unordered_map>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"

namespace lego {

namespace transport {

typedef std::function<void(int, transport::protobuf::Header&)> WaitCallbackFunction;

struct WaitItem {
    WaitItem(uint32_t msg_id, WaitCallbackFunction cb, int64_t timeout_us, int32_t cnt)
            : message_id(msg_id), callback(cb), count(cnt) {
        timeout = std::chrono::steady_clock::now() + std::chrono::microseconds(timeout_us);
    }
    uint32_t message_id;
    WaitCallbackFunction callback;
    int32_t count;
    std::chrono::steady_clock::time_point timeout;
};

typedef std::shared_ptr<WaitItem> WaitItemPtr;

class SynchroWait {
public:
    static SynchroWait* Instance();
    void Add(
            uint32_t msg_id,
            int64_t timeout_us,
            WaitCallbackFunction callback,
            int32_t count);
    void Callback(
            uint32_t msg_id,
            transport::protobuf::Header& message);

private:
    SynchroWait();
    ~SynchroWait();
    void Timeout(uint32_t msg_id);
    void Cancel(uint32_t msg_id);
    void Check();

    static const int32_t kTimeCheckoutPeriod = 1000u * 1000u;  // 1s

    std::unordered_map<uint32_t, WaitItemPtr> wait_map_;
    std::mutex wait_map_mutex_;
    common::IndependentTick tick_;

    DISALLOW_COPY_AND_ASSIGN(SynchroWait);
};

}  // namespace transport

}  // namespace lego
