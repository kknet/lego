#pragma once

#include "network/network_utils.h"
#include "root_congress/congress_utils.h"

namespace lego {

namespace congress {

struct ShardInfo {
    uint32_t network_id;
    uint32_t stake_sum;
    uint32_t overload;
};

typedef std::shared_ptr<ShardInfo> ShardInfoPtr;

class ConsensusShardManager {
public:
    ConsensusShardManager();
    ~ConsensusShardManager();

private:
    ShardInfoPtr shards_[network::kConsensusShardEndNetworkId];

    DISALLOW_COPY_AND_ASSIGN(ConsensusShardManager);
};

}  // namespace congress

}  // namespace lego
