#pragma once

#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "bft/bft_interface.h"
#include "bft/member_manager.h"
#include "bft/proto/bft.pb.h"

namespace lego {

namespace bft {

class BftManager {
public:
    static BftManager* Instance();
    // load bft code by bft addr
    int StartBft(
            const std::string& bft_address,
            const std::string& gid,
            uint32_t network_id,
            uint64_t rand_num);
    int AddBft(BftInterfacePtr& bft_ptr);
    BftInterfacePtr GetBft(const std::string& gid);
    void RemoveBft(const std::string& gid);
    void NetworkMemberChange(
            uint32_t network_id,
            MembersPtr& members_ptr,
            NodeIndexMapPtr& node_index_map);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    MembersPtr GetNetworkMembers(uint32_t network_id) {
        return mem_manager_->GetNetworkMembers(network_id);
    }
    void AddHeightToDb(BftInterfacePtr& bft_ptr);

private:
    BftManager();
    ~BftManager();
    void HandleMessage(transport::protobuf::Header& header);
    int InitBft(
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    int LeaderPrepare(BftInterfacePtr& bft_ptr);
    int BackupPrepare(
            BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    int LeaderPrecommit(
            BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    int BackupPrecommit(
            BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    int LeaderCommit(
            BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    int BackupCommit(
            BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);
    void CheckTimeout();
    int VerifySignature(
            uint32_t mem_index,
            const bft::protobuf::BftMessage& bft_msg,
            security::Signature& sign);
    int VerifySignatureWithBftMessage(const bft::protobuf::BftMessage& bft_msg);
    int VerifyLeaderSignature(
            BftInterfacePtr& bft_ptr,
            const bft::protobuf::BftMessage& bft_msg);
    int VerifyAggSignature(
            BftInterfacePtr& bft_ptr,
            const bft::protobuf::BftMessage& bft_msg);
    void LeaderBroadcastToAcc(const std::shared_ptr<bft::protobuf::Block>& block_ptr);
    void HandleToAccountTxBlock(
            transport::protobuf::Header& header,
            bft::protobuf::BftMessage& bft_msg);

    std::unordered_map<std::string, BftInterfacePtr> bft_hash_map_;
    std::mutex bft_hash_map_mutex_;
    std::shared_ptr<MemberManager> mem_manager_;
    common::Tick timeout_tick_;
    std::atomic<uint32_t> tps_{ 0 };
    std::atomic<uint32_t> pre_tps_{ 0 };
    uint64_t tps_btime_{ 0 };
    std::mutex all_test_mutex_;

    DISALLOW_COPY_AND_ASSIGN(BftManager);
};

}  // namespace bft

}  // namespace lego
