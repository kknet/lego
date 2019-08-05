#pragma once

#include <chrono>
#include <mutex>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "sync/proto/sync.pb.h"
#include "sync/sync_utils.h"

namespace lego {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace sync {

struct SyncItem {
    SyncItem(uint32_t net_id, const std::string& in_key, uint32_t pri)
            : network_id(net_id), key(in_key), priority(pri) {
        timeout = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(kSyncValueRetryPeriod);
    }

    uint32_t network_id{ 0 };
    std::string key;
    uint32_t priority{ 0 };
    uint32_t sync_times{ 0 };
    std::chrono::steady_clock::time_point timeout;
};

typedef std::shared_ptr<SyncItem> SyncItemPtr;

class KeyValueSync {
public:
    static KeyValueSync* Instance();
    int AddSync(uint32_t network_id, const std::string& key, uint32_t priority);
    void Init();
    void Destroy();
    void HandleMessage(transport::protobuf::Header& msg);

private:
    struct PrioSyncQueue {
        std::queue<SyncItemPtr> sync_queue;
        std::mutex mutex;
    };

    KeyValueSync();
    ~KeyValueSync();
    void CheckSyncItem();
    void CheckSyncTimeout();
    uint64_t SendSyncRequest(
            uint32_t network_id,
            const sync::protobuf::SyncMessage& sync_msg,
            const std::set<uint64_t>& sended_neigbors);
    void ProcessSyncValueRequest(
            transport::protobuf::Header& header,
            protobuf::SyncMessage& sync_msg);
    void ProcessSyncValueResponse(
            transport::protobuf::Header& header,
            protobuf::SyncMessage& sync_msg);

    std::unordered_map<std::string, SyncItemPtr> synced_map_;
    std::mutex synced_map_mutex_;
    PrioSyncQueue prio_sync_queue_[kMaxSyncPriority + 1];
    common::Tick tick_;
    common::Tick sync_timeout_tick_;

    DISALLOW_COPY_AND_ASSIGN(KeyValueSync);
};

}  // namespace sync

}  // namespace lego
