#include "stdafx.h"
#include "election/elect_dht.h"

namespace lego {

namespace elect {

ElectDht::ElectDht(transport::TransportPtr& transport, dht::NodePtr& local_node)
        : BaseDht(transport, local_node) {}

ElectDht::~ElectDht() {}

}  // namespace elect

}  // namespace lego
