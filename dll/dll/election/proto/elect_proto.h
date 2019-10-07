#pragma once

#include "transport/proto/transport.pb.h"
#include "dht/node.h"

namespace lego {

namespace elect {

class ElectProto {
public:
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    static void CreateElectBlock(
            const dht::NodePtr& local_node,
            transport::protobuf::Header& msg);

private:
    ElectProto() {}
    ~ElectProto() {}

    DISALLOW_COPY_AND_ASSIGN(ElectProto);
};

}  // namespace elect

}  // namespace lego
