#include "stdafx.h"
#include "transport/synchro_wait.h"

namespace lego {

namespace transport {

SynchroWait* SynchroWait::Instance() {
    static SynchroWait ins;
    return &ins;
}

void SynchroWait::Add(
        uint32_t msg_id,
        int64_t timeout_us,
        WaitCallbackFunction callback,
        int32_t count) {
    assert(callback);
    auto item_ptr = std::make_shared<WaitItem>(msg_id, callback, timeout_us, count);
    std::unique_lock<std::mutex> lock(wait_map_mutex_);
    wait_map_.insert(std::make_pair(msg_id, item_ptr));
}

void SynchroWait::Callback(
        uint32_t msg_id,
        transport::protobuf::Header& message) {
    WaitItemPtr item_ptr;
    {
        std::unique_lock<std::mutex> lock(wait_map_mutex_);
        auto iter = wait_map_.find(msg_id);
        if (iter == wait_map_.end()) {
            return;
        }

        item_ptr = iter->second;
        --(iter->second->count);
        if (iter->second->count <= 0) {
            wait_map_.erase(iter);
        }
    }

    if (item_ptr) {
        item_ptr->callback(kTransportSuccess, message);
    }
}

void SynchroWait::Timeout(uint32_t msg_id) {
    Cancel(msg_id);
}

void SynchroWait::Cancel(uint32_t msg_id) {
    WaitCallbackFunction callback;
    WaitItemPtr item_ptr;
    int32_t expect_count = 0;
    {
        std::unique_lock<std::mutex> lock(wait_map_mutex_);
        auto iter = wait_map_.find(msg_id);
        if (iter == wait_map_.end()) {
            return;
        }

        callback = iter->second->callback;
        expect_count = iter->second->count;
        wait_map_.erase(iter);
    }

    if (callback) {
        transport::protobuf::Header message;
		message.set_id(msg_id);
        for (int i = 0; i < expect_count; ++i) {
            callback(kTransportTimeout, message);
        }
    }
}

void SynchroWait::Check() {
    std::vector<uint32_t> message_vec;
    {
        std::unique_lock<std::mutex> lock(wait_map_mutex_);
        for (auto iter = wait_map_.begin(); iter != wait_map_.end(); ++iter) {
            auto tick_now = std::chrono::steady_clock::now();
            if (iter->second->timeout <= tick_now) {
                message_vec.push_back(iter->first);
            }
        }
    }

    for (uint32_t i = 0; i < message_vec.size(); ++i) {
        Timeout(message_vec[i]);
    }
    tick_.CutOff(kTimeCheckoutPeriod, std::bind(&SynchroWait::Check, this));
}

SynchroWait::SynchroWait() {
    tick_.CutOff(kTimeCheckoutPeriod, std::bind(&SynchroWait::Check, this));
}

SynchroWait::~SynchroWait() {
    tick_.Destroy();
}

}  // namespace transport

}  // namespace lego
