#include "transport/multi_thread/message_filter.h"

#include "transport/transport_utils.h"

namespace lego {

namespace transport {

MessageFilter* MessageFilter::Instance() {
    static MessageFilter ins;
    return &ins;
}

bool MessageFilter::CheckUnique(uint64_t msg_hash) {
    auto iter = unique_set_.find(msg_hash);
    if (iter != unique_set_.end()) {
        return true;
    }

    unique_set_.insert(msg_hash);
    if (unique_queue_.size() >= kUniqueMaxMessageCount) {
        unique_set_.erase(unique_queue_.front());
        unique_queue_.pop();
    }
    return false;
}

bool MessageFilter::StopBroadcast(transport::protobuf::Header& header) {
    if (!header.has_broadcast()) {
        return false;
    }

    assert(header.has_hash());
    uint32_t stop_times = header.broadcast().stop_times();
    if (stop_times <= 0) {
        stop_times = kBroadcastMaxRelayTimes;
    }

    auto iter = broadcast_stop_map_.find(header.hash());
    if (iter != broadcast_stop_map_.end()) {
        if (iter->second >= stop_times) {
            return true;
        }
    } else {
        broadcast_stop_map_[header.hash()] = 1;
    }

    if (broadcast_stop_queue_.size() >= kBroadcastMaxMessageCount) {
        broadcast_stop_map_.erase(broadcast_stop_queue_.front());
        broadcast_stop_queue_.pop();
    }
    return false;
}

MessageFilter::MessageFilter()
        : broadcast_stop_map_(4 * kBroadcastMaxMessageCount),
          unique_set_(4 * kUniqueMaxMessageCount) {}

MessageFilter::~MessageFilter() {}

}  // namespace transport

}  // namespace lego
