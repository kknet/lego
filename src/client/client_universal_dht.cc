#include "client/client_universal_dht.h"

#include "transport/synchro_wait.h"
#include "client/proto/client.pb.h"

namespace lego {

namespace client {

ClientUniversalDht::ClientUniversalDht(
        transport::TransportPtr& transport_ptr,
        dht::NodePtr& local_node)
        : dht::BaseDht(transport_ptr, local_node) {}

ClientUniversalDht::~ClientUniversalDht() {}

void ClientUniversalDht::HandleMessage(transport::protobuf::Header& msg) {
    if (msg.type() != common::kServiceMessage) {
        return dht::BaseDht::HandleMessage(msg);
    }

    protobuf::ServiceMessage svr_msg;
    if (!svr_msg.ParseFromString(msg.data())) {
        return;
    }

    if (svr_msg.has_vpn_res()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("client callback", msg);
        transport::SynchroWait::Instance()->Callback(msg.id(), msg);
    }
}

void ClientUniversalDht::SetFrequently(transport::protobuf::Header& msg) {
    dht::BaseDht::SetFrequently(msg);
    msg.set_client(true);
}

}  // namespace client

}  // namespace lego
