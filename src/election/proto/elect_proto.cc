#include "stdafx.h"
#include "election/proto/elect_proto.h"

#include <limits>

#include "common/country_code.h"
#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "dht/base_dht.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "election/proto/elect.pb.h"
#include "election/elect_utils.h"

namespace lego {

namespace elect {

void ElectProto::SetDefaultBroadcastParam(
        transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(kElectBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kElectBroadcastStopTimes);
    broad_param->set_hop_limit(kElectHopLimit);
    broad_param->set_hop_to_layer(kElectHopToLayer);
    broad_param->set_neighbor_count(kElectNeighborCount);
}

void ElectProto::CreateElectBlock(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    dht::DhtKeyManager dht_key(4, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(true);
    msg.set_hop_count(0);

    auto dht = network::DhtManager::Instance()->GetDht(4);
	if (!dht) {
		std::cout << "get network: " << common::GlobalInfo::Instance()->network_id() << " failed" << std::endl;
	}
	assert(dht);
    auto readonly_dht = dht->readonly_hash_sort_dht();
    if (readonly_dht->size() < 2) {
        return;
    }
    // now just for test
    protobuf::ElectMessage ec_msg;
    auto ec_block = ec_msg.mutable_elect_block();
    auto in = ec_block->add_in();
    in->set_id(local_node->id);
    in->set_pubkey(security::Schnorr::Instance()->str_pubkey());
    in->set_sign("sign");
    in->set_net_id(4);
    in->set_country(common::global_country_map["US"]);

    for (auto iter = readonly_dht->begin(); iter != readonly_dht->end(); ++iter) {
        auto in = ec_block->add_in();
        in->set_id((*iter)->id);
        in->set_pubkey((*iter)->pubkey_str);
        in->set_sign("sign");
        in->set_net_id(4);
        in->set_country(common::global_country_map["US"]);
    }

    ec_block->set_acc_pubkey("acc_pubkey");
    ec_block->set_acc_sign("acc_sign");

    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(ec_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("create ec block: ") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

}  // namespace elect

}  // namespace lego
