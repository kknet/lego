#pragma once

#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "client/proto/client.pb.h"

namespace lego {

namespace client {

class ClientProto {
public:
    static void CreateGetVpnInfoRequest(
            const dht::NodePtr& local_node,
            const dht::NodePtr& des_node,
            uint32_t msg_id,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(des_node->dht_key);
        msg.set_des_dht_key_hash(des_node->dht_key_hash);
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_id(msg_id);
        msg.set_type(common::kServiceMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::ServiceMessage svr_msg;
        auto vpn_req = svr_msg.mutable_vpn_req();
        vpn_req->set_pubkey(security::Schnorr::Instance()->str_pubkey());
        msg.set_data(svr_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
        msg.set_debug(std::string("CreateGetVpnInfoRequest:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(des_node->dht_key));
        DHT_DEBUG("begin: %s", msg.debug().c_str());
#endif
    }

private:
    ClientProto();
    ~ClientProto();

    DISALLOW_COPY_AND_ASSIGN(ClientProto);
};

}  // namespace client

}  // namespace lego
