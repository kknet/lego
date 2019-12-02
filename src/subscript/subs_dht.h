#pragma once

#include <chrono>
#include <mutex>
#include <unordered_map>

#include "dht/base_dht.h"
#include "dht/node.h"
#include "subscript/subs_utils.h"

namespace lego {

namespace subs {

class SubsDht : public dht::BaseDht {
public:
    SubsDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
    virtual ~SubsDht();

private:

    DISALLOW_COPY_AND_ASSIGN(SubsDht);
};

}  // namespace subs

}  // namespace lego
