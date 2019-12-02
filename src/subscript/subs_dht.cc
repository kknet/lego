#include "stdafx.h"
#include "subscript/subs_dht.h"

#include "common/global_info.h"
#include "network/route.h"

namespace lego {

namespace subs {

SubsDht::SubsDht(
        transport::TransportPtr& transport,
        dht::NodePtr& local_node)
        : BaseDht(transport, local_node) {}

SubsDht::~SubsDht() {}

}  // namespace subs

}  // namespace lego
