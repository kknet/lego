#include "sync/key_value_sync.h"

#include "db/db.h"
#include "transport/proto/transport.pb.h"
#include "dht/base_dht.h"
#include "network/dht_manager.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "block/block_manager.h"
#include "sync/sync_utils.h"
#include "sync/proto/sync_proto.h"

namespace lego {

namespace sync {

KeyValueSync* KeyValueSync::Instance() {
    static KeyValueSync ins;
    return &ins;
}

KeyValueSync::KeyValueSync() {
    //Init();
}

KeyValueSync::~KeyValueSync() {}

int KeyValueSync::AddSync(uint32_t network_id, const std::string& key, uint32_t priority) {
    assert(priority <= kSyncHighest);
    if (db::Db::Instance()->Exist(key)) {
        return kSyncKeyExsits;
    }

    {
        std::lock_guard<std::mutex> guard(synced_map_mutex_);
        auto tmp_iter = synced_map_.find(key);
        if (tmp_iter != synced_map_.end()) {
            SYNC_ERROR("added sync item [%d] [%s]", network_id, common::Encode::HexEncode(key).c_str());
            return kSyncKeyAdded;
        }
    }

    auto item = std::make_shared<SyncItem>(network_id, key, priority);
    {
        std::lock_guard<std::mutex> guard(prio_sync_queue_[priority].mutex);
        prio_sync_queue_[priority].sync_queue.push(item);
    }
    SYNC_ERROR("new sync item [%d] [%s]", network_id, common::Encode::HexEncode(key).c_str());
    return kSyncSuccess;
}

void KeyValueSync::Init() {
    tick_.CutOff(kSyncTickPeriod, std::bind(&KeyValueSync::CheckSyncItem, this));
    sync_timeout_tick_.CutOff(
            kTimeoutCheckPeriod,
            std::bind(&KeyValueSync::CheckSyncTimeout, this));
}

void KeyValueSync::Destroy() {
    tick_.Destroy();
    sync_timeout_tick_.Destroy();
}

void KeyValueSync::CheckSyncItem() {
    std::set<uint64_t> sended_neigbors;
    std::map<uint32_t, sync::protobuf::SyncMessage> sync_dht_map;
    bool stop = false;
    for (uint32_t i = kSyncHighest; i >= kSyncPriLowest; --i) {
        std::lock_guard<std::mutex> guard(prio_sync_queue_[i].mutex);
        while (!prio_sync_queue_[i].sync_queue.empty()) {
            auto& item = prio_sync_queue_[i].sync_queue.front();

            {
                std::lock_guard<std::mutex> guard(synced_map_mutex_);
                auto tmp_iter = synced_map_.find(item->key);
                if (tmp_iter != synced_map_.end()) {
                    prio_sync_queue_[i].sync_queue.pop();
                    continue;
                }
            }
            

            auto iter = sync_dht_map.find(item->network_id);
            if (iter == sync_dht_map.end()) {
                sync_dht_map[item->network_id] = sync::protobuf::SyncMessage();
            }
            auto sync_req = sync_dht_map[item->network_id].mutable_sync_value_req();
            sync_req->add_keys(item->key);
            prio_sync_queue_[i].sync_queue.pop();
            if (static_cast<uint32_t>(sync_req->keys_size()) > kMaxSyncKeyCount) {
                uint64_t choose_node = SendSyncRequest(
                        item->network_id,
                        sync_dht_map[item->network_id],
                        sended_neigbors);
                if (choose_node != 0) {
                    sended_neigbors.insert(choose_node);
                }

                sync_req->clear_keys();
                if (sended_neigbors.size() > kSyncNeighborCount) {
                    stop = true;
                    break;
                }
            }
            item->timeout = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(kSyncValueRetryPeriod);
            ++(item->sync_times);
            {
                std::lock_guard<std::mutex> tmp_guard(synced_map_mutex_);
                synced_map_.insert(std::make_pair(item->key, item));
                if (synced_map_.size() > kSyncMaxKeyCount) {
                    stop = true;
                    break;
                }
            }
        }

        if (stop) {
            break;
        }
    }

    for (auto iter = sync_dht_map.begin(); iter != sync_dht_map.end(); ++iter) {
        if (iter->second.sync_value_req().keys_size() > 0) {
            uint64_t choose_node = SendSyncRequest(
                iter->first,
                iter->second,
                sended_neigbors);
            if (choose_node != 0) {
                sended_neigbors.insert(choose_node);
            }
        }
    }
    tick_.CutOff(kSyncTickPeriod, std::bind(&KeyValueSync::CheckSyncItem, this));
}

uint64_t KeyValueSync::SendSyncRequest(
        uint32_t network_id,
        const sync::protobuf::SyncMessage& sync_msg,
        const std::set<uint64_t>& sended_neigbors) {
    auto dht = network::DhtManager::Instance()->GetDht(network_id);
    if (!dht) {
        SYNC_ERROR("network id[%d] not exists.", network_id);
        return 0;
    }
    dht::DhtPtr readonly_dht = dht->readonly_dht();
    if (readonly_dht->empty()) {
        SYNC_ERROR("network id[%d] no neighbors.", network_id);
        return 0;
    }
    uint32_t rand_pos = std::rand() % readonly_dht->size();
    uint32_t choose_pos = rand_pos - 1;
    if (rand_pos == 0) {
        choose_pos = readonly_dht->size() - 1;
    }

    dht::NodePtr node = nullptr;
    while (rand_pos != choose_pos) {
        auto iter = sended_neigbors.find((*readonly_dht)[rand_pos]->id_hash);
        if (iter != sended_neigbors.end()) {
            ++rand_pos;
            if (rand_pos >= readonly_dht->size()) {
                rand_pos = 0;
            }
            continue;
        }

        node = (*readonly_dht)[rand_pos];
        break;
    }

    if (!node) {
        node = (*readonly_dht)[0];
    }

    transport::protobuf::Header msg;
    SyncProto::CreateSyncValueReqeust(dht->local_node(), node, sync_msg, msg);
    dht->transport()->Send(node->public_ip, node->public_port, 0, msg);
    SYNC_ERROR("sent sync request [%s:%d]", node->public_ip.c_str(), node->public_port);
    return node->id_hash;
}

void KeyValueSync::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kSyncMessage);
    protobuf::SyncMessage sync_msg;
    if (!sync_msg.ParseFromString(header.data())) {
        DHT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    if (sync_msg.has_sync_value_req()) {
        ProcessSyncValueRequest(header, sync_msg);
    }

    if (sync_msg.has_sync_value_res()) {
        ProcessSyncValueResponse(header, sync_msg);
    }
}

void KeyValueSync::ProcessSyncValueRequest(
        transport::protobuf::Header& header,
        protobuf::SyncMessage& sync_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    assert(sync_msg.has_sync_value_req());
    auto dht = network::DhtManager::Instance()->GetDht(
            sync_msg.sync_value_req().network_id());
    if (!dht) {
        SYNC_ERROR("sync from network[%u] not exists",
                sync_msg.sync_value_req().network_id());
        return;
    }
    protobuf::SyncMessage res_sync_msg;
    auto sync_res = res_sync_msg.mutable_sync_value_res();
    auto value_map = sync_res->mutable_values();
    uint32_t add_size = 0;
    for (int32_t i = 0; i < sync_msg.sync_value_req().keys_size(); ++i) {
        const std::string& key = sync_msg.sync_value_req().keys(i);
        std::string value;
        if (db::Db::Instance()->Get(key, &value).ok()) {
            (*value_map)[key] = value;
            add_size += key.size() + value.size();
            if (add_size >= kSyncPacketMaxSize) {
                break;
            }
        }
    }

    if (add_size == 0) {
        return;
    }

    transport::protobuf::Header msg;
    SyncProto::CreateSyncValueResponse(dht->local_node(), header, res_sync_msg, msg);
    dht->transport()->Send(header.from_ip(), header.from_port(), 0, msg);
}

void KeyValueSync::ProcessSyncValueResponse(
        transport::protobuf::Header& header,
        protobuf::SyncMessage& sync_msg) {
    assert(sync_msg.has_sync_value_res());
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    auto& res_map = sync_msg.sync_value_res().values();
    for (auto iter = res_map.begin(); iter != res_map.end(); ++iter) {
        SYNC_ERROR("recv sync response [%s]", common::Encode::HexEncode(iter->first).c_str());

        bft::protobuf::Block block_item;
        if (block_item.ParseFromString(iter->second)) {
            // block string
            if (block_item.hash() == iter->first) {

                block::BlockManager::Instance()->AddNewBlock(block_item);
                continue;
            }
        }

        db::Db::Instance()->Put(iter->first, iter->second);
        {
            std::lock_guard<std::mutex> guard(synced_map_mutex_);
            auto tmp_iter = synced_map_.find(iter->first);
            if (tmp_iter != synced_map_.end()) {
                synced_map_.erase(tmp_iter);
            }
        }
    }
}

void KeyValueSync::CheckSyncTimeout() {
    auto tp_now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> guard(synced_map_mutex_);
    for (auto iter = synced_map_.begin(); iter != synced_map_.end();) {
        if (iter->second->timeout <= tp_now) {
            if (iter->second->sync_times >= kSyncMaxRetryTimes) {
                synced_map_.erase(iter++);
                continue;
            }

            {
                std::lock_guard<std::mutex> tmp_guard(prio_sync_queue_[iter->second->priority].mutex);
                prio_sync_queue_[iter->second->priority].sync_queue.push(iter->second);
            }
        }
        ++iter;
    }
}

}  // namespace sync

}  // namespace lego