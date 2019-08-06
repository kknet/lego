#pragma once

#include "common/utils.h"
#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "nat_traverse/proto/nat.pb.h"

namespace lego {

namespace nat {

class NatProto {
public:
    static void CreateDetectionRequest(
            const dht::NodePtr& local_node,
            const dht::NodePtr& des_node,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(des_node->dht_key);
        msg.set_priority(transport::kTransportPriorityHighest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kNatMessage);
        msg.set_client(local_node->client_mode);
        msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        // TODO(tt): add sign
        nat::protobuf::NatMessage nat_msg;
        auto detection_req = nat_msg.mutable_detection_req();
        detection_req->set_public_ip(local_node->public_ip);
        detection_req->set_public_port(local_node->public_port);
        detection_req->set_local_ip(local_node->local_ip);
        detection_req->set_local_port(local_node->local_port);
        detection_req->set_id(local_node->id);
        detection_req->set_nat_type(local_node->nat_type);
        detection_req->set_dht_key(local_node->dht_key);
        detection_req->set_client(local_node->client_mode);
        msg.set_data(nat_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
        msg.set_debug(std::string("DetectionRequest:") +
            local_node->public_ip + ":" +
            std::to_string(local_node->public_port) + ", to " +
            des_node->public_ip + ":" + std::to_string(des_node->public_port));
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin:", msg);
#endif
    }

private:
    NatProto() {}
    ~NatProto() {}

    DISALLOW_COPY_AND_ASSIGN(NatProto);
};

}  // namespace nat

}  // namespace lego
