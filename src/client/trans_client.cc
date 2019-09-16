#include "client/trans_client.h"

#include "common/encode.h"
#include "transport/proto/transport.pb.h"
#include "security/schnorr.h"
#include "network/universal.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "client/proto/client_proto.h"

namespace lego {

namespace client {

TransactionClient* TransactionClient::Instance() {
    static TransactionClient ins;
    return &ins;
}

int TransactionClient::Transaction(
        const std::string& to,
        uint64_t amount,
        std::string& tx_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return kClientError;
    }
    tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    uint32_t type = common::kConsensusTransaction;
    if (to.empty()) {
        type = common::kConsensusCreateAcount;
    }

    ClientProto::CreateTxRequest(
            uni_dht->local_node(),
            tx_gid,
            to,
            amount,
            rand_num,
            type,
            msg);
    network::Route::Instance()->Send(msg);
    tx_gid = common::Encode::HexEncode(tx_gid);
    return kClientSuccess;
}

int TransactionClient::VpnLogin(
        const std::string& svr_account,
        const std::vector<std::string>& route_vec) {
    return kClientSuccess;
}

int TransactionClient::VpnLogout() {
    return kClientSuccess;
}

}  // namespace client

}  // namespace lego
