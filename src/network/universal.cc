#include "network/universal.h"

#include "common/global_info.h"
#include "common/state_lock.h"
#include "common/country_code.h"
#include "ip/ip_utils.h"
#include "transport/synchro_wait.h"
#include "dht/dht_key.h"
#include "dht/dht_function.h"
#include "network/network_utils.h"
#include "network/universal_manager.h"
#include "network/proto/network_proto.h"

namespace lego {

namespace network {

Uniersal::Uniersal(transport::TransportPtr& transport_ptr, dht::NodePtr& local_node)
        : BaseDht(transport_ptr, local_node) {
}

Uniersal::~Uniersal() {
    Destroy();
}

int Uniersal::Init() {
    if (BaseDht::Init() != dht::kDhtSuccess) {
        NETWORK_ERROR("init base dht failed!");
        return kNetworkError;
    }

    universal_ids_ = new bool[kNetworkMaxDhtCount];
    std::fill(universal_ids_, universal_ids_ + kNetworkMaxDhtCount, false);

    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key);
    if (net_id == kUniversalNetworkId) {
        AddNetworkId(net_id);
    } else {
        dht::BaseDhtPtr dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
        if (dht) {
            auto universal_dht = std::dynamic_pointer_cast<Uniersal>(dht);
            if (universal_dht) {
                universal_dht->AddNetworkId(net_id);
            }
        }
    }
    return kNetworkSuccess;
}

bool Uniersal::CheckDestination(const std::string& des_dht_key, bool closest) {
    if (dht::BaseDht::CheckDestination(des_dht_key, closest)) {
        return true;
    }

    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(des_dht_key);
    if (!HasNetworkId(net_id)) {
        return false;
    }

    const auto& node = UniversalManager::Instance()->GetUniversal(net_id)->local_node();
    if (node->dht_key != des_dht_key) {
        return false;
    }
    return true;
}

void Uniersal::SetFrequently(transport::protobuf::Header& msg) {
    dht::BaseDht::SetFrequently(msg);
    msg.set_universal(true);
}

std::vector<dht::NodePtr> Uniersal::LocalGetNetworkNodes(
        uint32_t network_id,
        uint32_t count) {
    return LocalGetNetworkNodes(
            network_id,
            ip::kInvalidCountryCode,
            count);
}

std::vector<dht::NodePtr> Uniersal::RemoteGetNetworkNodes(
        uint32_t network_id,
        uint32_t count) {
    return RemoteGetNetworkNodes(
            network_id,
            ip::kInvalidCountryCode,
            count);
}

std::vector<dht::NodePtr> Uniersal::LocalGetNetworkNodes(
        uint32_t network_id,
        uint32_t country,
        uint32_t count) {
    dht::Dht tmp_dht = *(readonly_dht());  // change must copy
    dht::DhtKeyManager dht_key(
            network_id,
            country,
            true);
    auto local_nodes = dht::DhtFunction::GetClosestNodes(
            tmp_dht,
            dht_key.StrKey(),
            dht::kDhtNearestNodesCount);
    std::vector<dht::NodePtr> tmp_nodes;
    for (uint32_t i = 0; i < local_nodes.size(); ++i) {
        auto net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_nodes[i]->dht_key);
        uint8_t find_country = dht::DhtKeyManager::DhtKeyGetCountry(local_nodes[i]->dht_key);
        if (country == ip::kInvalidCountryCode) {
            if (net_id == network_id &&
                    local_nodes[i]->public_node) {
                tmp_nodes.push_back(local_nodes[i]);
            }
        } else {
            if (net_id == network_id &&
                    find_country == country &&
                    local_nodes[i]->public_node) {
                tmp_nodes.push_back(local_nodes[i]);
            }
        }
    }
    return tmp_nodes;
}

std::vector<dht::NodePtr> Uniersal::RemoteGetNetworkNodes(
        uint32_t network_id,
        uint32_t country,
        uint32_t count) {
    // may be can try 3 times for random destination dht key
    transport::protobuf::Header msg;
    SetFrequently(msg);
    NetworkProto::CreateGetNetworkNodesRequest(local_node(), network_id, country, count, msg);
    SendToClosestNode(msg);
    std::vector<dht::NodePtr> nodes;
    common::StateLock state_lock(0);
    auto callback = [&state_lock, &nodes](int status, transport::protobuf::Header& header) {
        do  {
            if (status != transport::kTransportSuccess) {
                break;
            }

            if (header.type() != common::kNetworkMessage) {
                break;
            }

            protobuf::NetworkMessage network_msg;
            if (!network_msg.ParseFromString(header.data())) {
                break;
            }

            if (!network_msg.has_get_net_nodes_res()) {
                break;
            }

            const auto& res_nodes = network_msg.get_net_nodes_res().nodes();
            for (int32_t i = 0; i < res_nodes.size(); ++i) {
                auto pubkey_ptr = std::make_shared<security::PublicKey>(res_nodes[i].pubkey());
                nodes.push_back(std::make_shared<dht::Node>(
                        res_nodes[i].id(),
                        res_nodes[i].dht_key(),
                        res_nodes[i].nat_type(),
                        false,
                        res_nodes[i].public_ip(),
                        res_nodes[i].public_port(),
                        res_nodes[i].local_ip(),
                        res_nodes[i].local_port(),
                        pubkey_ptr));
            }
        } while (0);
        state_lock.Signal();
    };
    transport::SynchroWait::Instance()->Add(msg.id(), 1000 * 1000, callback, 1);
    state_lock.Wait();
    return nodes;
}

void Uniersal::HandleMessage(transport::protobuf::Header& msg) {
    if (msg.type() == common::kDhtMessage || msg.type() == common::kNatMessage) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("universal dht:", msg);
        return dht::BaseDht::HandleMessage(msg);
    }

    if (msg.type() != common::kNetworkMessage) {
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("universal network:", msg);
    protobuf::NetworkMessage network_msg;
    if (!network_msg.ParseFromString(msg.data())) {
        DHT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    if (network_msg.has_get_net_nodes_req()) {
        ProcessGetNetworkNodesRequest(msg, network_msg);
    }

    if (network_msg.has_get_net_nodes_res()) {
        ProcessGetNetworkNodesResponse(msg, network_msg);
    }
}

void Uniersal::ProcessGetNetworkNodesRequest(
        transport::protobuf::Header& header,
        protobuf::NetworkMessage& network_msg) {
    std::vector<dht::NodePtr> nodes = LocalGetNetworkNodes(
            network_msg.get_net_nodes_req().net_id(),
            network_msg.get_net_nodes_req().country(),
            network_msg.get_net_nodes_req().count());
    if (nodes.empty()) {
        SendToClosestNode(header);
        return;
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    NetworkProto::CreateGetNetworkNodesResponse(local_node_, header, nodes, msg);
    SendToClosestNode(msg);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end 2", header);
}

void Uniersal::ProcessGetNetworkNodesResponse(
        transport::protobuf::Header& header,
        protobuf::NetworkMessage& network_msg) {
    if (header.des_dht_key() != local_node_->dht_key) {
        SendToClosestNode(header);
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    transport::SynchroWait::Instance()->Callback(header.id(), header);
}

void Uniersal::AddNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    universal_ids_[network_id] = true;
}

void Uniersal::RemoveNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    universal_ids_[network_id] = false;
}

bool Uniersal::HasNetworkId(uint32_t network_id) {
    assert(network_id < kNetworkMaxDhtCount);
    return universal_ids_[network_id];
}

int Uniersal::Destroy() {
    if (universal_ids_ != nullptr) {
        delete []universal_ids_;
    }

    dht::BaseDhtPtr dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    if (dht == nullptr) {
        return kNetworkSuccess;
    }
    auto universal_dht = std::dynamic_pointer_cast<Uniersal>(dht);
    if (universal_dht == nullptr) {
        return kNetworkSuccess;
    }
    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key);
    universal_dht->RemoveNetworkId(net_id);
    return kNetworkSuccess;
}

}  // namespace network

}  //namespace lego
