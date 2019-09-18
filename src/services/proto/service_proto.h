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
            const transport::protobuf::Header& header,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(header.src_dht_key());
        msg.set_des_dht_key_hash(common::Hash::Hash64(header.src_dht_key()));
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_id(header.id());
        msg.set_universal(true);
        msg.set_type(common::kServiceMessage);
        if (header.client()) {
            msg.set_from_ip(header.from_ip());
            msg.set_from_port(header.from_port());
            msg.set_client(header.client());
            msg.set_client_relayed(true);
            msg.set_client_proxy(header.client_proxy());
            msg.set_client_dht_key(header.client_dht_key());
            msg.set_client_handled(true);
        }
        msg.set_hop_count(0);
        msg.set_des_node_id(header.src_node_id());  // client must fill this field
        msg.set_data(svr_msg.SerializeAsString());
    }

private:
    ServiceProto();
    ~ServiceProto();
    DISALLOW_COPY_AND_ASSIGN(ServiceProto);
};

}  // namespace service

}  // namespace lego
