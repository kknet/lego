#include "root_congress/consensus_shard_manager.h"

namespace lego {

namespace congress {

ConsensusShardManager::ConsensusShardManager() {
    std::fill(shards_, shards_ + network::kConsensusShardEndNetworkId, nullptr);
}

ConsensusShardManager::~ConsensusShardManager() {}

}  // namespace congress

}  // namespace lego
