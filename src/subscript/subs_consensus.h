#pragma once

#include "common/tick.h"
#include "init/network_init.h"
#include "network/shard_network.h"
#include "subscript/subs_dht.h"
#include "subscript/subs_utils.h"

namespace lego {

namespace subs {

typedef network::ShardNetwork<SubsDht> SubsDhtNode;
typedef std::shared_ptr<SubsDhtNode> SubsDhtNodePtr;

class SubsConsensus : public init::NetworkInit {
public:
    static SubsConsensus* Instance();
    virtual int Init(int argc, char** argv);

private:
    SubsConsensus();
    ~SubsConsensus();

    void HandleMessage(transport::protobuf::Header& header);
    int StartSubscription();

    SubsDhtNodePtr subs_node_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(SubsConsensus);
};

}  // namespace vpn

}  // namespace lego
