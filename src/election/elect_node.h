#pragma once

#include "common/utils.h"
#include "network/universal.h"
#include "network/network_utils.h"
#include "election/elect_dht.h"

namespace lego {

namespace elect {

class ElectNode {
public:
    explicit ElectNode(uint32_t network_id);
    ~ElectNode();
    int Init();
    void Destroy();

private:
    int JoinUniversal();
    int JoinShard();

    dht::BaseDhtPtr universal_role_{ nullptr };
    dht::BaseDhtPtr elect_dht_{ nullptr };
    uint32_t network_id_{ network::kNetworkMaxDhtCount };
    transport::TransportPtr transport_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(ElectNode);
};

}  // namespace elect

}  // namespace lego
