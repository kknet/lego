#pragma once

#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "services/proto/service.pb.h"

namespace lego {

namespace service {

class ServiceProto {
public:
    static void CreateGetVpnInfoRes(
            const dht::NodePtr& local_node,
            const protobuf::ServiceMessage& svr_msg,
            const transport::protobuf::Header& from_header,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(from_header.src_dht_key());
        msg.set_des_dht_key_hash(common::Hash::Hash64(from_header.src_dht_key()));
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_id(from_header.id());
        msg.set_type(common::kServiceMessage);
        if (from_header.client()) {
            msg.set_client(from_header.client());
            msg.set_client_relayed(true);
        }
        msg.set_hop_count(0);
        msg.set_des_node_id(from_header.src_node_id());  // client must fill this field
        msg.set_data(svr_msg.SerializeAsString());
    }

private:
    ServiceProto();
    ~ServiceProto();
    DISALLOW_COPY_AND_ASSIGN(ServiceProto);
};

}  // namespace service

}  // namespace lego
