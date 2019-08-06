#include "election/elect_manager.h"

#include "common/utils.h"
#include "network/route.h"
#include "bft/bft_manager.h"

namespace lego {

namespace elect {

ElectManager::ElectManager() {
    network::Route::Instance()->RegisterMessage(
            common::kElectMessage,
            std::bind(&ElectManager::HandleMessage, this, std::placeholders::_1));
}

ElectManager::~ElectManager() {}

int ElectManager::Join(uint32_t network_id) {
    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter != elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkJoined;
        }
    }

    auto elect_node = std::make_shared<ElectNode>(network_id);
    if (elect_node->Init() != network::kNetworkSuccess) {
        ELECT_ERROR("node join network [%u] failed!", network_id);
        return kElectError;
    }

    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter != elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkJoined;
        }
        elect_network_map_[network_id] = elect_node;
    }

    return kElectSuccess;
}

int ElectManager::Quit(uint32_t network_id) {
    ElectNodePtr elect_node = nullptr;
    {
        std::lock_guard<std::mutex> guard(elect_network_map_mutex_);
        auto iter = elect_network_map_.find(network_id);
        if (iter == elect_network_map_.end()) {
            ELECT_INFO("this node has join network[%u]", network_id);
            return kElectNetworkNotJoined;
        }
        elect_node = iter->second;
        elect_network_map_.erase(iter);
    }
    elect_node->Destroy();
    return kElectSuccess;
}

void ElectManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kElectMessage);
    protobuf::ElectMessage ec_msg;
    if (!ec_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (ec_msg.has_elect_block()) {
        ProcessNewElectBlock(header, ec_msg);
    }
}

void ElectManager::ProcessNewElectBlock(
        transport::protobuf::Header& header,
        protobuf::ElectMessage& elect_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    assert(elect_msg.has_elect_block());
    std::map<uint32_t, bft::MembersPtr> in_members;
    std::map<uint32_t, bft::MembersPtr> out_members;
    std::map<uint32_t, bft::NodeIndexMapPtr> in_index_members;
    auto in = elect_msg.elect_block().in();
    for (int32_t i = 0; i < in.size(); ++i) {
        auto net_id = in[i].net_id();
        auto iter = in_members.find(net_id);
        if (iter == in_members.end()) {
            in_members[net_id] = std::make_shared<bft::Members>();
            in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
        }
        security::PublicKey pubkey(in[i].pubkey());
        security::CommitSecret secret;
        in_members[net_id]->push_back(std::make_shared<bft::BftMember>(
                net_id, in[i].id(), in[i].pubkey(), i));
        in_index_members[net_id]->insert(std::make_pair(in[i].id(), i));
    }

    for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
        auto index_map_iter = in_index_members.find(iter->first);
        assert(index_map_iter != in_index_members.end());
        bft::BftManager::Instance()->NetworkMemberChange(
                iter->first,
                iter->second,
                index_map_iter->second);
    }
}

}  // namespace elect

}  // namespace lego
