#include "network/dht_manager.h"

#include <cassert>
#include <algorithm>

#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "dht/proto/dht_proto.h"
#include "network/universal_manager.h"
#include "network/universal.h"

namespace lego {

namespace network {

DhtManager* DhtManager::Instance() {
    static DhtManager ins;
    return &ins;
}

void DhtManager::Init() {
    Destroy();
    dhts_ = new dht::BaseDhtPtr[kNetworkMaxDhtCount];
    std::fill(dhts_, dhts_ + kNetworkMaxDhtCount, nullptr);
    tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
    std::cout << "DhtManager tick_: " << tick_.tick_index() << std::endl;
}

void DhtManager::Destroy() {
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        dht_map_.clear();
    }

    if (dhts_ != nullptr) {
        for (uint32_t i = 0; i < kNetworkMaxDhtCount; ++i) {
            if (dhts_[i] != nullptr) {
                dhts_[i]->Destroy();
                dhts_[i] = nullptr;
            }
        }
        delete []dhts_;
        dhts_ = nullptr;
    }
}

void DhtManager::RegisterDht(uint32_t net_id, dht::BaseDhtPtr& dht) {
    assert(net_id < kNetworkMaxDhtCount);
    assert(dhts_[net_id] == nullptr);
    dhts_[net_id] = dht;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        dht_map_[net_id] = dht;
    }
}

void DhtManager::UnRegisterDht(uint32_t net_id) {
    assert(net_id < kNetworkMaxDhtCount);
    assert(dhts_[net_id] != nullptr);
    dhts_[net_id]->Destroy();
    dhts_[net_id] = nullptr;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        auto iter = dht_map_.find(net_id);
        if (iter != dht_map_.end()) {
            dht_map_.erase(iter);
        }
    }
}

dht::BaseDhtPtr DhtManager::GetDht(uint32_t net_id) {
    assert(net_id < kNetworkMaxDhtCount);
    return dhts_[net_id];
}

DhtManager::DhtManager() {}

DhtManager::~DhtManager() {
    Destroy();
}

void DhtManager::NetworkDetection() {
    std::vector<dht::BaseDhtPtr> detect_dhts;
    {
        std::lock_guard<std::mutex> guard(dht_map_mutex_);
        for (auto iter = dht_map_.begin(); iter != dht_map_.end(); ++iter) {
            if (iter->second->readonly_dht()->size() <= kNetworkDetectionLimitNum) {
                detect_dhts.push_back(iter->second);
            }
        }
    }

    auto dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    auto universal_dht = std::dynamic_pointer_cast<Uniersal>(dht);
    if (!universal_dht) {
        tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
        return;
    }
    for (auto iter = detect_dhts.begin(); iter != detect_dhts.end(); ++iter) {
        uint32_t network_id = dht::DhtKeyManager::DhtKeyGetNetId(
                (*iter)->local_node()->dht_key);
        auto nodes = universal_dht->RemoteGetNetworkNodes(
                network_id,
                std::numeric_limits<uint8_t>::max(),
                4);
        if (nodes.empty()) {
            continue;
        }

        auto node = nodes[std::rand() % nodes.size()];
        if (node->dht_key_hash == (*iter)->local_node()->dht_key_hash) {
            continue;
        }

        if ((*iter)->Join(node) != dht::kDhtSuccess) {
            continue;
        }
        transport::protobuf::Header msg;
        (*iter)->SetFrequently(msg);
        // just connect
        dht::DhtProto::CreateConnectRequest((*iter)->local_node(), node, true, msg);
        (*iter)->transport()->Send(
                node->public_ip,
                node->public_port,
                0,
                msg);
    }

    tick_.CutOff(kNetworkDetectPeriod, std::bind(&DhtManager::NetworkDetection, this));
}

}  // namespace network

}  // namespace lego
