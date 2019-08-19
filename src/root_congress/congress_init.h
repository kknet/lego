#pragma once

#include "network/shard_network.h"
#include "root_congress/congress_utils.h"
#include "root_congress/congress_dht.h"

namespace lego {

namespace congress {

typedef network::ShardNetwork<CongressDht> CongressNode;
typedef std::shared_ptr<CongressNode> CongressNodePtr;

class CongressInit {
public:
	CongressInit();
	~CongressInit();
	int Init();

private:
	CongressNodePtr congress_node_{ nullptr };

	DISALLOW_COPY_AND_ASSIGN(CongressInit);
};

}  // namespace congress

}  // namespace lego
