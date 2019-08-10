#pragma once

#include "common/utils.h"
#include "dht/node.h"
#include "transport/proto/transport.pb.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_interface.h"

namespace lego {

namespace bft {

class BftProto {
public:
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    static void LeaderCreatePrepare(
            const dht::NodePtr& local_node,
            const std::string& data,
            const BftInterfacePtr& bft_ptr,
            const security::Signature& sign,
            transport::protobuf::Header& msg);
    static void BackupCreatePrepare(
            const transport::protobuf::Header& from_header,
            const bft::protobuf::BftMessage& from_bft_msg,
            const dht::NodePtr& local_node,
            const std::string& data,
            const security::CommitSecret& secret,
            bool agree,
            transport::protobuf::Header& msg);
    static void LeaderCreatePreCommit(
            const dht::NodePtr& local_node,
            const BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& msg);
    static void BackupCreatePreCommit(
            const transport::protobuf::Header& from_header,
            const bft::protobuf::BftMessage& from_bft_msg,
            const dht::NodePtr& local_node,
            const std::string& data,
            const security::Response& agg_res,
            bool agree,
            transport::protobuf::Header& msg);
    static void LeaderCreateCommit(
            const dht::NodePtr& local_node,
            const BftInterfacePtr& bft_ptr,
            transport::protobuf::Header& msg);
    static void LeaderBroadcastToAccount(
            const dht::NodePtr& local_node,
            uint32_t net_id,
            const std::shared_ptr<bft::protobuf::Block>& block_ptr,
            transport::protobuf::Header& msg);

private:
    DISALLOW_COPY_AND_ASSIGN(BftProto);
};

}  // namespace bft

}  // namespace lego
