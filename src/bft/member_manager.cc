#include "bft/member_manager.h"

#include <cassert>

#include "network/network_utils.h"

namespace lego {

namespace bft {

MemberManager::MemberManager() {
    network_members_ = new MembersPtr[network::kConsensusShardEndNetworkId];
    std::fill(
            network_members_,
            network_members_ + network::kConsensusShardEndNetworkId,
            nullptr);
    node_index_map_ = new NodeIndexMapPtr[network::kConsensusShardEndNetworkId];
    std::fill(
            node_index_map_,
            node_index_map_ + network::kConsensusShardEndNetworkId,
            nullptr);
}

MemberManager::~MemberManager() {
    if (network_members_ != nullptr) {
        delete []network_members_;
    }
}

void MemberManager::SetNetworkMember(
        uint32_t network_id,
        MembersPtr& members_ptr,
        NodeIndexMapPtr& node_index_map) {
    std::lock_guard<std::mutex> guard(all_mutex_);
    assert(network_id < network::kConsensusShardEndNetworkId);  // just shard
    assert(!members_ptr->empty());
    network_members_[network_id] = members_ptr;
    node_index_map_[network_id] = node_index_map;
}

MembersPtr MemberManager::GetNetworkMembers(uint32_t network_id) {
    std::lock_guard<std::mutex> guard(all_mutex_);
    assert(network_id < network::kConsensusShardEndNetworkId);  // just shard
    return network_members_[network_id];
}

bool MemberManager::IsLeader(
        uint32_t network_id,
        const std::string& node_id,
        uint64_t rand) {
    std::lock_guard<std::mutex> guard(all_mutex_);
    assert(network_id < network::kConsensusShardEndNetworkId);  // just shard
    MembersPtr member_ptr = network_members_[network_id];
    if (member_ptr == nullptr) {
        return false;
    }
    assert(member_ptr != nullptr);
    assert(!member_ptr->empty());
    uint32_t node_idx = rand % member_ptr->size();
    auto mem_ptr = (*member_ptr)[node_idx];
    assert(mem_ptr != nullptr);
    return mem_ptr->id == node_id;
}

uint32_t MemberManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    std::lock_guard<std::mutex> guard(all_mutex_);
    assert(network_id < network::kConsensusShardEndNetworkId);  // just shard
    assert(node_index_map_[network_id] != nullptr);
    NodeIndexMapPtr node_index_map = node_index_map_[network_id];
    assert(node_index_map != nullptr);
    assert(!node_index_map->empty());
    auto iter = node_index_map->find(node_id);
    assert(iter != node_index_map->end());
    return iter->second;
}

BftMemberPtr MemberManager::GetMember(
        uint32_t network_id,
        const std::string& node_id) {
    assert(network_id < network::kConsensusShardEndNetworkId);  // just shard
    uint32_t mem_index = GetMemberIndex(network_id, node_id);
    std::lock_guard<std::mutex> guard(all_mutex_);
    MembersPtr member_ptr = network_members_[network_id];
    assert(member_ptr != nullptr);
    assert(!member_ptr->empty());
    return (*member_ptr)[mem_index];
}

BftMemberPtr MemberManager::GetMember(uint32_t network_id, uint32_t index) {
    std::lock_guard<std::mutex> guard(all_mutex_);
    MembersPtr member_ptr = network_members_[network_id];
    assert(member_ptr != nullptr);
    assert(!member_ptr->empty());
    return (*member_ptr)[index];
}

}  // namespace bft

}  // namespace lego
