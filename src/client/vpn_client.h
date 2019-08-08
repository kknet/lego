#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <mutex>

namespace lego {

namespace transport {
    class Transport;
    typedef std::shared_ptr<Transport> TransportPtr;
    namespace protobuf {
        class Header;
    }
}  // namespace transport

namespace dht {
    class Node;
    typedef std::shared_ptr<Node> NodePtr;
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace client {

class ClientUniversalDht;
typedef std::shared_ptr<ClientUniversalDht> ClientUniversalDhtPtr;

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
    static VpnClient* Instance();
    std::string Init(const std::string& conf);
    std::string GetVpnServerNodes(
            const std::string& country,
            uint32_t count,
            std::vector<VpnServerNodePtr>& nodes);
    std::string Transaction(const std::string& to, uint64_t amount, std::string& tx_gid);
    std::string CheckTransaction(const std::string& tx_gid);

private:
    VpnClient();
    ~VpnClient();

    void HandleMessage(transport::protobuf::Header& header);
    int InitTransport();
    int SetPriAndPubKey(const std::string& prikey);
    int InitNetworkSingleton(const std::string& conf);
    int GetVpnNodes(
            const std::vector<dht::NodePtr>& nodes,
            std::vector<VpnServerNodePtr>& vpn_nodes);
    int CreateClientUniversalNetwork();

    static const uint32_t kDefaultUdpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultUdpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kTestCreateAccountPeriod = 100u * 1000u;
    static const int64_t kTestNewElectPeriod = 10ll * 1000ll * 1000ll;

    transport::TransportPtr transport_{ nullptr };
    bool inited_{ false };
    std::mutex init_mutex_;
    ClientUniversalDhtPtr root_dht_{ nullptr };
    bool client_mode_{ false };
    uint32_t send_buff_size_{ kDefaultUdpSendBufferSize };
    uint32_t recv_buff_size_{ kDefaultUdpRecvBufferSize };
};

}  // namespace client

}  // namespace lego
