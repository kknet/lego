#include "client/client_universal_dht.h"

namespace lego {

namespace client {

ClientUniversalDht::ClientUniversalDht(
        transport::TransportPtr& transport_ptr,
        dht::NodePtr& local_node)
        : network::Uniersal(transport_ptr, local_node) {}

ClientUniversalDht::~ClientUniversalDht() {}

void ClientUniversalDht::HandleMessage(transport::protobuf::Header& msg) {

}

void ClientUniversalDht::SetFrequently(transport::protobuf::Header& msg) {
    network::Uniersal::SetFrequently(msg);
    msg.set_client(true);
}

}  // namespace client

}  // namespace lego
