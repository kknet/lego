#pragma once

#include <vector>

#include "common/utils.h"
#include "common/config.h"
#include "transport/transport.h"
#include "client/client_universal_dht.h"

namespace lego {

namespace dht {
    class Node;
    typedef std::shared_ptr<Node> NodePtr;
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace client {

struct VpnServerNode {
    VpnServerNode(
            const std::string& in_ip,
            uint16_t in_port,
            const std::string& enc_type,
            const std::string& pwd)
            : ip(in_ip), port(in_port), encrypt_type(enc_type), passwd(pwd) {}
    std::string ip;
    uint16_t port;
    std::string encrypt_type;
    std::string passwd;
};
typedef std::shared_ptr<VpnServerNode> VpnServerNodePtr;

class VpnClient {
public:
    VpnClient();
    ~VpnClient();
    int Init(const std::string& conf);
    int GetVpnServerNodes(
            const std::string& country,
            uint32_t count,
            std::vector<VpnServerNodePtr>& nodes);

private:
    void HandleMessage(transport::protobuf::Header& header);
    int InitTransport();
    int SetPriAndPubKey(const std::string& prikey);
    int InitNetworkSingleton();
    int GetVpnNodes(
            const std::vector<dht::NodePtr>& nodes,
            std::vector<VpnServerNodePtr>& vpn_nodes);
    int CreateClientUniversalNetwork();
    int CreateAccountAddress();

    static const uint32_t kDefaultUdpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultUdpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kTestCreateAccountPeriod = 100u * 1000u;
    static const int64_t kTestNewElectPeriod = 10ll * 1000ll * 1000ll;

    common::Config conf_;
    transport::TransportPtr transport_{ nullptr };
    bool inited_{ false };
    std::mutex init_mutex_;
    ClientUniversalDhtPtr root_dht_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(VpnClient);
};

}  // namespace client

}  // namespace lego
