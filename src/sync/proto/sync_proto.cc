#include "sync/proto/sync_proto.h"

#include "common/global_info.h"

namespace lego {

namespace sync {

void SyncProto::CreateSyncValueReqeust(
        const dht::NodePtr& local_node,
        const dht::NodePtr& des_node,
        const sync::protobuf::SyncMessage& sync_msg,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(des_node->dht_key);
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kSyncMessage);
    msg.set_client(local_node->client_mode);
    msg.set_data(sync_msg.SerializeAsString());
    msg.set_hop_count(0);
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("SyncValueReqeust:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            des_node->public_ip + "-" + std::to_string(des_node->public_port));
    DHT_DEBUG("begin: %s", msg.debug().c_str());
#endif
}

void SyncProto::CreateSyncValueResponse(
        const dht::NodePtr& local_node,
        const transport::protobuf::Header& header,
        const sync::protobuf::SyncMessage& sync_msg,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(header.id());
    msg.set_type(common::kSyncMessage);
    msg.set_client(local_node->client_mode);
    msg.set_data(sync_msg.SerializeAsString());
    msg.set_hop_count(0);
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("SyncValueResponse:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            header.from_ip() + "-" + std::to_string(header.from_port()));
    DHT_DEBUG("begin: %s", msg.debug().c_str());
#endif
}

}  // namespace sync

}  //namespace lego

