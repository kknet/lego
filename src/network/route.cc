#include "network/route.h"

#include "transport/processor.h"
#include "dht/dht_key.h"
#include "broadcast/filter_broadcast.h"
#include "network/universal.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/network_utils.h"

namespace lego {

namespace network {

Route* Route::Instance() {
    static Route ins;
    return &ins;
}

void Route::Init() {
    Destroy();
    // all message come route
    RegisterMessage(
            common::kDhtMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kNatMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kNetworkMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kRelayMessage,
            std::bind(&Route::RouteByUniversal, this, std::placeholders::_1));
    broadcast_ = std::make_shared<broadcast::FilterBroadcast>();
}

void Route::Destroy() {
    UnRegisterMessage(common::kDhtMessage);
    UnRegisterMessage(common::kNatMessage);
    UnRegisterMessage(common::kNetworkMessage);
    broadcast_.reset();
}

int Route::SendToLocal(transport::protobuf::Header& message) {
    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(message.des_dht_key());
    dht::BaseDhtPtr dht_ptr{ nullptr };
    if (message.universal()) {
        dht_ptr = UniversalManager::Instance()->GetUniversal(des_net_id);
    } else {
        dht_ptr = DhtManager::Instance()->GetDht(des_net_id);
    }
    assert(dht_ptr);
    dht_ptr->transport()->SendToLocal(message);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("SendToLocal", message);
    return kNetworkSuccess;
}

int Route::Send(transport::protobuf::Header& message) {
    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(message.des_dht_key());
    dht::BaseDhtPtr dht_ptr{ nullptr };
    if (message.universal()) {
        dht_ptr = UniversalManager::Instance()->GetUniversal(des_net_id);
    } else {
        dht_ptr = DhtManager::Instance()->GetDht(des_net_id);
    }

    if (dht_ptr != nullptr) {
        if (message.has_broadcast()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("call broadcast", message);
            broadcast_->Broadcasting(dht_ptr, message);
        } else {
            if (message.has_to_ip() && message.has_to_port()) {
                LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("call unicast direct", message);
                dht_ptr->transport()->Send(message.to_ip(), message.to_port(), 0, message);
            } else {
                LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("call unicast closest", message);
                dht_ptr->SendToClosestNode(message);
            }
        }
        return kNetworkSuccess;
    }
    // this node not in this network, relay by universal
    RouteByUniversal(message);
    return kNetworkSuccess;
}

void Route::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() < common::kLegoMaxMessageTypeCount);

    if (header.type() == common::kServiceMessage) {
        std::cout << "coming 1" << std::endl;
    }
    if (message_processor_[header.type()] == nullptr) {
        RouteByUniversal(header);
        return;
    }
    if (header.type() == common::kServiceMessage) {
        std::cout << "coming 2" << std::endl;
    }
    // every route message must use dht
    auto dht = GetDht(header.des_dht_key(), header.universal());
    if (!dht) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(
                std::string("no dht, route by universal: ") +
                std::to_string(header.universal()),
                header);
        RouteByUniversal(header);
        return;
    }
    if (header.type() == common::kServiceMessage) {
        std::cout << "coming 3" << std::endl;
    }

    if (!header.handled()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("call func", header);
        message_processor_[header.type()](header);
    }
    if (header.type() == common::kServiceMessage) {
        std::cout << "coming 4" << std::endl;
    }

    if (header.has_broadcast()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("broadcast it", header);
        Broadcast(header);
    }
    if (header.type() == common::kServiceMessage) {
        std::cout << "coming 5" << std::endl;
    }
}

void Route::HandleDhtMessage(transport::protobuf::Header& header) {
    auto dht = GetDht(header.des_dht_key(), header.universal());
    assert(dht);
    dht->HandleMessage(header);
}

void Route::RegisterMessage(uint32_t type, transport::MessageProcessor proc) {
    assert(type < common::kLegoMaxMessageTypeCount);
    assert(message_processor_[type] == nullptr);
    message_processor_[type] = proc;
    transport::Processor::Instance()->RegisterProcessor(
            type,
            std::bind(&Route::HandleMessage, this, std::placeholders::_1));
}

void Route::UnRegisterMessage(uint32_t type) {
    assert(type < common::kLegoMaxMessageTypeCount);
    message_processor_[type] = nullptr;
}

Route::Route() {}

Route::~Route() {
    Destroy();
}

void Route::Broadcast(transport::protobuf::Header& header) {
    assert(header.has_broadcast());
    assert(header.has_des_dht_key());
    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(header.des_dht_key());
    auto des_dht = GetDht(header.des_dht_key(), header.universal());
    assert(des_dht);
    uint32_t src_net_id = kNetworkMaxDhtCount;
    if (header.has_src_dht_key()) {
        src_net_id = dht::DhtKeyManager::DhtKeyGetNetId(header.src_dht_key());
    }

    auto broad_param = header.mutable_broadcast();
    if (src_net_id != des_net_id) {
        if (!broad_param->net_crossed()) {
            broad_param->set_net_crossed(true);
            broad_param->clear_bloomfilter();
            header.set_hop_count(0);
        }
    }
    broadcast_->Broadcasting(des_dht, header);
}

dht::BaseDhtPtr Route::GetDht(const std::string& dht_key, bool universal) {
    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(dht_key);
    dht::BaseDhtPtr dht = nullptr;
    if (universal) {
        dht = UniversalManager::Instance()->GetUniversal(net_id);
    } else {
        dht = DhtManager::Instance()->GetDht(net_id);
    }
    return dht;
}

void Route::RouteByUniversal(transport::protobuf::Header& header) {
    auto universal_dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    assert(universal_dht);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("route by universal", header);
    universal_dht->SendToClosestNode(header);
}

}  // namespace network

}  // namespace lego