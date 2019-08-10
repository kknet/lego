#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <mutex>
#include <unordered_map>

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

struct TxInfo {
    TxInfo(const std::string& in_to, uint64_t in_balance, uint32_t h, const std::string& hash)
            : to(in_to), balance(in_balance), height(h), block_hash(hash) {}
    std::string to;
    uint64_t balance;
    uint32_t height;
    std::string block_hash;
};
typedef std::shared_ptr<TxInfo> TxInfoPtr;

class VpnClient {
public:
    static VpnClient* Instance();
    std::string Init(
            const std::string& local_ip,
            uint16_t local_port,
            const std::string& bootstrap);
    std::string Init(const std::string& conf);
    std::string GetVpnServerNodes(
            const std::string& country,
            uint32_t count,
            std::vector<VpnServerNodePtr>& nodes);
    std::string Transaction(const std::string& to, uint64_t amount, std::string& tx_gid);
    std::string GetTransactionInfo(const std::string& tx_gid);
    int GetSocket();

private:
    VpnClient();
    ~VpnClient();

    void HandleMessage(transport::protobuf::Header& header);
    int InitTransport();
    int SetPriAndPubKey(const std::string& prikey);
    int InitNetworkSingleton();
    int GetVpnNodes(
            const std::vector<dht::NodePtr>& nodes,
            std::vector<VpnServerNodePtr>& vpn_nodes);
    int CreateClientUniversalNetwork();
    void CheckTxExists();
    std::string CheckTransaction(const std::string& tx_gid);
    void WriteDefaultLogConf();
    bool ConfigExists();

    static const uint32_t kDefaultUdpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultUdpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kTestCreateAccountPeriod = 100u * 1000u;
    static const int64_t kTestNewElectPeriod = 10ll * 1000ll * 1000ll;
    static const uint32_t kCheckTxPeriod = 1 * 1000 * 1000;

    transport::TransportPtr transport_{ nullptr };
    bool inited_{ false };
    std::mutex init_mutex_;
    ClientUniversalDhtPtr root_dht_{ nullptr };
    bool client_mode_{ true };
    uint32_t send_buff_size_{ kDefaultUdpSendBufferSize };
    uint32_t recv_buff_size_{ kDefaultUdpRecvBufferSize };
    std::unordered_map<std::string, TxInfoPtr> tx_map_;
    std::mutex tx_map_mutex_;
};

}  // namespace client

}  // namespace lego
