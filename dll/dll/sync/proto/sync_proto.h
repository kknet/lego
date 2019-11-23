#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "sync/proto/sync.pb.h"

namespace lego {

namespace sync {

class SyncProto {
public:
    static void CreateSyncValueReqeust(
            const dht::NodePtr& local_node,
            const dht::NodePtr& des_node,
            const sync::protobuf::SyncMessage& sync_msg,
            transport::protobuf::Header& msg);
    static void CreateSyncValueResponse(
            const dht::NodePtr& local_node,
            const transport::protobuf::Header& header,
            const sync::protobuf::SyncMessage& sync_msg,
            transport::protobuf::Header& msg);

private:
    SyncProto() {}
    ~SyncProto() {}

    DISALLOW_COPY_AND_ASSIGN(SyncProto);
};

}  // namespace sync

}  //namespace lego

