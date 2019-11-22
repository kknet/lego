#include "stdafx.h"
#include "election/elect_node.h"

#include "common/global_info.h"
#include "dht/dht_key.h"
#include "dht/node.h"
#include "transport/udp/udp_transport.h"
#include "network/universal_manager.h"
#include "network/universal.h"
#include "network/bootstrap.h"
#include "network/dht_manager.h"
#include "election/elect_utils.h"
#include "election/elect_dht.h"

namespace lego {

namespace elect {

ElectNode::ElectNode(uint32_t network_id) : network_id_(network_id) {
	common::GlobalInfo::Instance()->set_network_id(network_id_);
}

ElectNode::~ElectNode() {}

int ElectNode::Init() {
    if (JoinShard() != kElectSuccess) {
        return kElectJoinShardFailed;
    }

    if (JoinUniversal() != kElectSuccess) {
        ELECT_ERROR("create universal network failed!");
        return kElectJoinUniversalError;
    }
    return kElectSuccess;
}

void ElectNode::Destroy() {
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
int ElectNode::JoinUniversal() {
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
    universal_role_ = std::make_shared<network::Universal>(
            tansport_ptr,
            local_node);
    if (universal_role_->Init() != network::kNetworkSuccess) {
        ELECT_ERROR("init universal role dht failed!");
        return kElectError;
    }
    network::UniversalManager::Instance()->RegisterUniversal(network_id_, universal_role_);
    if (universal_role_->Bootstrap(
            network::Bootstrap::Instance()->root_bootstrap()) != dht::kDhtSuccess) {
        ELECT_ERROR("join universal network failed!");
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id_);
        return kElectError;
    }
    return kElectSuccess;
}

int ElectNode::JoinShard() {
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
    elect_dht_ = std::make_shared<ElectDht>(
            tansport_ptr,
            local_node);
    if (elect_dht_->Init() != network::kNetworkSuccess) {
        ELECT_ERROR("init shard role dht failed!");
        return kElectError;
    }
    network::DhtManager::Instance()->RegisterDht(network_id_, elect_dht_);
    auto boot_nodes = network::Bootstrap::Instance()->GetNetworkBootstrap(network_id_, 3);
    std::cout << "boot nodes: " << boot_nodes.size() << std::endl;
    if (boot_nodes.empty()) {
        return kElectSuccess;
    }

    if (elect_dht_->Bootstrap(boot_nodes) != dht::kDhtSuccess) {
        ELECT_ERROR("join universal network failed!");
        return kElectError;
    }
    return kElectSuccess;
}

}  // namespace elect

}  // namespace lego
