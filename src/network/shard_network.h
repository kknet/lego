#pragma once

#include "common/utils.h"
#include "dht/dht_key.h"
#include "network/universal.h"
#include "network/network_utils.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/bootstrap.h"
#include "election/elect_dht.h"

namespace lego {

namespace network {

template<class DhtType>
class ShardNetwork {
public:
    explicit ShardNetwork(uint32_t network_id);
    ~ShardNetwork();
    int Init();
    void Destroy();

private:
    int JoinUniversal();
    int JoinShard();

    dht::BaseDhtPtr universal_role_{ nullptr };
    dht::BaseDhtPtr elect_dht_{ nullptr };
    uint32_t network_id_{ network::kNetworkMaxDhtCount };
    transport::TransportPtr transport_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(ShardNetwork);
};

template<class DhtType>
ShardNetwork<DhtType>::ShardNetwork(uint32_t network_id) : network_id_(network_id) {}

template<class DhtType>
ShardNetwork<DhtType>::~ShardNetwork() {}

template<class DhtType>
int ShardNetwork<DhtType>::Init() {
    if (JoinShard() != kNetworkSuccess) {
        return kNetworkJoinShardFailed;
    }

    if (JoinUniversal() != kNetworkSuccess) {
        NETWORK_ERROR("create universal network failed!");
        return kNetworkJoinUniversalError;
    }
    return kNetworkSuccess;
}

template<class DhtType>
void ShardNetwork<DhtType>::Destroy() {
    if (universal_role_) {
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id_);
        universal_role_->Destroy();
        universal_role_.reset();
    }

    if (elect_dht_) {
        network::DhtManager::Instance()->UnRegisterDht(network_id_);
        elect_dht_->Destroy();
        elect_dht_.reset();
    }
}

// every one should join universal
template<class DhtType>
int ShardNetwork<DhtType>::JoinUniversal() {
    auto unversal_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(unversal_dht);
    assert(unversal_dht->transport());
    assert(unversal_dht->local_node());
    auto local_node = std::make_shared<dht::Node>(*unversal_dht->local_node());
    uint8_t country = dht::DhtKeyManager::DhtKeyGetCountry(local_node->dht_key);
    dht::DhtKeyManager dht_key(network_id_, country, local_node->id);
    local_node->dht_key = dht_key.StrKey();
    local_node->dht_key_hash = common::Hash::Hash64(dht_key.StrKey());
    transport::TransportPtr tansport_ptr = unversal_dht->transport();
    universal_role_ = std::make_shared<network::Uniersal>(
        tansport_ptr,
        local_node);
    if (universal_role_->Init() != network::kNetworkSuccess) {
        NETWORK_ERROR("init universal role dht failed!");
        return kNetworkError;
    }
    network::UniversalManager::Instance()->RegisterUniversal(network_id_, universal_role_);
    if (universal_role_->Bootstrap(
            network::Bootstrap::Instance()->root_bootstrap()) != dht::kDhtSuccess) {
        NETWORK_ERROR("join universal network failed!");
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id_);
        return kNetworkError;
    }
    return kNetworkSuccess;
}

template<class DhtType>
int ShardNetwork<DhtType>::JoinShard() {
    auto unversal_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(unversal_dht);
    assert(unversal_dht->transport());
    assert(unversal_dht->local_node());
    auto local_node = std::make_shared<dht::Node>(*unversal_dht->local_node());
    uint8_t country = dht::DhtKeyManager::DhtKeyGetCountry(local_node->dht_key);
    dht::DhtKeyManager dht_key(network_id_, country, local_node->id);
    local_node->dht_key = dht_key.StrKey();
    local_node->dht_key_hash = common::Hash::Hash64(dht_key.StrKey());
    transport::TransportPtr tansport_ptr = unversal_dht->transport();
    elect_dht_ = std::make_shared<DhtType>(
        tansport_ptr,
        local_node);
    if (elect_dht_->Init() != network::kNetworkSuccess) {
        NETWORK_ERROR("init shard role dht failed!");
        return kNetworkError;
    }
    network::DhtManager::Instance()->RegisterDht(network_id_, elect_dht_);
    auto boot_nodes = network::Bootstrap::Instance()->GetNetworkBootstrap(network_id_, 3);
    std::cout << "boot nodes: " << boot_nodes.size() << std::endl;
    if (boot_nodes.empty()) {
        return kNetworkSuccess;
    }

    if (elect_dht_->Bootstrap(boot_nodes) != dht::kDhtSuccess) {
        NETWORK_ERROR("join universal network failed!");
        return kNetworkError;
    }
    return kNetworkSuccess;
}

}  // namespace network

}  // namespace lego
