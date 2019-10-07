#pragma once

#include "common/utils.h"
#include "dht/base_dht.h"

namespace lego {

namespace elect {

class ElectDht : public dht::BaseDht {
public:
    ElectDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
    virtual ~ElectDht();

private:

    DISALLOW_COPY_AND_ASSIGN(ElectDht);
};

}  // namespace elect

}  // namespace lego
