#pragma once

#include "common/utils.h"
#include "common/global_info.h"
#include "common/bloom_filter.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/proto/dht.pb.h"
#include "dht/node.h"
#include "dht/base_dht.h"

namespace lego {

namespace dht {

class DhtProto {
public:
    static void SetFreqMessage(BaseDhtPtr& dht, transport::protobuf::Header& msg);
    static void CreateBootstrapRequest(
            const NodePtr& local_node,
            const NodePtr& des_node,
            int32_t get_init_msg,
            transport::protobuf::Header& msg);
    static void CreateBootstrapResponse(
            int32_t get_init_msg,
            const NodePtr& local_node,
            const transport::protobuf::Header& header,
            transport::protobuf::Header& msg);
    static void CreateRefreshNeighborsRequest(
            const Dht& dht,
            const NodePtr& local_node,
            const NodePtr& des_node,
        transport::protobuf::Header& msg);
    static void CreateRefreshNeighborsResponse(
            const NodePtr& local_node,
            const transport::protobuf::Header& header,
            const std::vector<NodePtr>& nodes,
            transport::protobuf::Header& msg);
    static void CreateHeatbeatRequest(
            const NodePtr& local_node,
            const NodePtr& des_node,
            transport::protobuf::Header& msg);
    static void CreateHeatbeatResponse(
            const NodePtr& local_node,
            transport::protobuf::Header& header,
            transport::protobuf::Header& msg);
    static void CreateConnectRequest(
            const NodePtr& local_node,
            const NodePtr& des_node,
            bool direct,
            transport::protobuf::Header& msg);

private:
    DhtProto() {}
    ~DhtProto() {}

    DISALLOW_COPY_AND_ASSIGN(DhtProto);
};

}  // namespace dht

}  //namespace lego

