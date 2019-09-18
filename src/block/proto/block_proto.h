#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "block/proto/block.pb.h"

namespace lego {

namespace block {

class BlockProto {
public:
    static void CreateGetBlockResponse(
            const dht::NodePtr& local_node,
            const transport::protobuf::Header& header,
            const std::string& block_data,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(header.src_dht_key());
        msg.set_priority(transport::kTransportPriorityLow);
        msg.set_id(header.id());
        msg.set_type(common::kBlockMessage);
        msg.set_universal(header.universal());
        if (header.client()) {
            msg.set_from_ip(header.from_ip());
            msg.set_from_port(header.from_port());
            msg.set_client(header.client());
            msg.set_client_relayed(true);
            msg.set_client_proxy(header.client_proxy());
            msg.set_client_dht_key(header.client_dht_key());
            msg.set_des_dht_key(header.client_dht_key());
            msg.set_des_dht_key_hash(common::Hash::Hash64(header.client_dht_key()));
            msg.set_client_handled(true);
        }
        msg.set_hop_count(0);
        msg.set_data(block_data);
#ifdef LEGO_TRACE_MESSAGE
        msg.set_debug(std::string("GetBlockResponse: ") +
                local_node->public_ip + "-" +
                std::to_string(local_node->public_port) + ", to " +
                common::Encode::HexEncode(msg.des_dht_key()));
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
    }

    static void AccountAttrRequest(
            const dht::NodePtr& local_node,
            const std::string& account,
            const std::string& attr,
            uint64_t height,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account);
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_des_dht_key_hash(common::Hash::Hash64(dht_key.StrKey()));
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_universal(true);
        msg.set_type(common::kBlockMessage);
        msg.set_hop_count(0);
        msg.set_client(false);
        block::protobuf::BlockMessage block_msg;
        auto attr_req = block_msg.mutable_acc_attr_req();
        attr_req->set_account(account);
        attr_req->set_attr_key(attr);
        attr_req->set_height(height);
        msg.set_data(block_msg.SerializeAsString());
    }
private:
    BlockProto();
    ~BlockProto();
    DISALLOW_COPY_AND_ASSIGN(BlockProto);
};

}  // namespace block

}  // namespace lego
