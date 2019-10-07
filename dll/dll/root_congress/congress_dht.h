#pragma once

#include "dht/base_dht.h"
#include "root_congress/congress_utils.h"

namespace lego {

namespace congress {

class CongressDht : public dht::BaseDht {
public:
	CongressDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
	virtual ~CongressDht();

private:

	DISALLOW_COPY_AND_ASSIGN(CongressDht);
};

}  // namespace congress

}  // namespace lego
