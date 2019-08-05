#pragma once

#include <unordered_map>

#include "security/public_key.h"
#include "security/commit_secret.h"
#include "dht/node.h"
#include "bft/bft_utils.h"

namespace lego {

namespace bft {

struct BftMember {
    BftMember(uint32_t nid, const std::string& in_id, const std::string& pkey, uint32_t idx)
            : net_id(nid), id(in_id), pubkey(pkey), index(idx) {}
    uint32_t net_id;
    std::string id;
    security::PublicKey pubkey;
    uint32_t index;
    security::CommitSecret secret;
};

typedef std::shared_ptr<BftMember> BftMemberPtr;
typedef std::vector<BftMemberPtr> Members;
typedef std::shared_ptr<Members> MembersPtr;

typedef std::shared_ptr<std::unordered_map<std::string, uint32_t>> NodeIndexMapPtr;

class MemberManager {
public:
    MemberManager();
    ~MemberManager();

    void SetNetworkMember(
            uint32_t network_id,
            MembersPtr& members_ptr,
            NodeIndexMapPtr& node_index_map);
    bool IsLeader(uint32_t network_id, const std::string& node_id, uint64_t rand);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    MembersPtr GetNetworkMembers(uint32_t network_id);
    BftMemberPtr GetMember(uint32_t network_id, const std::string& node_id);
    BftMemberPtr GetMember(uint32_t network_id, uint32_t index);

private:
    MembersPtr* network_members_;
    NodeIndexMapPtr* node_index_map_;

    DISALLOW_COPY_AND_ASSIGN(MemberManager);
};

}  // namespace bft

}  // namespace lego
