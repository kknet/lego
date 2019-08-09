#include "client/vpn_client.h"

#include <cassert>

#include "common/log.h"
#include "common/utils.h"
#include "common/config.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "common/state_lock.h"
#include "common/split.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/schnorr.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread.h"
#include "transport/synchro_wait.h"
#include "transport/transport_utils.h"
#include "transport/proto/transport.pb.h"
#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "network/bootstrap.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal.h"
#include "client/client_utils.h"
#include "client/proto/client.pb.h"
#include "client/proto/client_proto.h"
#include "client/client_universal_dht.h"

namespace lego {

namespace client {

static const uint32_t kDefaultBufferSize = 1024u * 1024u;
static common::Config config;

VpnClient::VpnClient() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
}

VpnClient::~VpnClient() {}

VpnClient* VpnClient::Instance() {
    static VpnClient ins;
    return &ins;
}

void VpnClient::HandleMessage(transport::protobuf::Header& header) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("client end", header);
    if (header.type() == common::kServiceMessage) {
        root_dht_->HandleMessage(header);
    }

    if (header.type() == common::kBlockMessage) {
        transport::SynchroWait::Instance()->Callback(header.id(), header);
    }
}

int VpnClient::GetSocket() {
    return transport_->GetSocket();
}

std::string VpnClient::Init(const std::string& conf) {
    if (!config.Init(conf)) {
        return "init config failed";
    }

    if (common::GlobalInfo::Instance()->Init(config) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return "init global failed";
    }

    std::string priky("");
    if (SetPriAndPubKey(priky) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "set pri and pub key fauled!";
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        CLIENT_ERROR("init ecdh create secret key failed!");
        return "ecdh init failed!";
    }

    if (InitTransport() != kClientSuccess) {
        CLIENT_ERROR("InitTransport failed!");
        return "init transport failed!";
    }

    if (InitNetworkSingleton() != kClientSuccess) {
        CLIENT_ERROR("InitNetworkSingleton failed!");
        return "init network failed!";
    }

    if (priky.empty()) {
        std::string tx_gid;
        if (Transaction("", 0, tx_gid) != "OK") {
            return "tx create acc failed!";
        }
        std::cout << "tx gid: " << common::Encode::HexEncode(tx_gid) << std::endl;
        std::this_thread::sleep_for(std::chrono::microseconds(1000000ull));
        if (CheckTransaction(tx_gid) != "OK") {
            std::cout << "check transaction failed!" << std::endl;
            CLIENT_ERROR("check transaction failed!");
            return "check transaction failed!";
        }
        return "create account success!";
        std::cout << "create account success!" << std::endl;
    }
    return "OK";
}

std::string VpnClient::Init(
        const std::string& local_ip,
        uint16_t local_port,
        const std::string& bootstrap) {
    FILE* file = NULL;
    file = fopen("/data/data/com.vm.legovpn/log4cpp.properties", "w");
    if (file == NULL) {
        return "create file failed2!";
    }
    std::string log_str = ("# log4cpp.properties\n"
        "log4cpp.rootCategory = DEBUG\n"
        "log4cpp.category.sub1 = DEBUG, programLog\n"
        "log4cpp.appender.rootAppender = ConsoleAppender\n"
        "log4cpp.appender.rootAppender.layout = PatternLayout\n"
        "log4cpp.appender.rootAppender.layout.ConversionPattern = %d [%p] %m%n\n"
        "log4cpp.appender.programLog = RollingFileAppender\n"
        "log4cpp.appender.programLog.fileName = /data/data/com.vm.legovpn/lego.log\n"
        "log4cpp.appender.programLog.maxFileSize = 1073741824\n"
        "log4cpp.appender.programLog.maxBackupIndex = 1\n"
        "log4cpp.appender.programLog.layout = PatternLayout\n"
        "log4cpp.appender.programLog.layout.ConversionPattern = %d [%p] %m%n\n");
    fwrite(log_str.c_str(), log_str.size(), 1, file);
    fclose(file); 
    log4cpp::PropertyConfigurator::configure("/data/data/com.vm.legovpn/log4cpp.properties");

    config.Set("lego", "local_ip", local_ip);
    config.Set("lego", "local_port", local_port);
    config.Set("lego", "country", "US");
    config.Set("lego", "first_node", false);
    config.Set("lego", "id", "id_cleint_1");
    config.Set("lego", "client", true);
    config.Set("lego", "bootstrap", bootstrap);
    if (common::GlobalInfo::Instance()->Init(config) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return "init global failed";
    }

    std::string priky("");
    if (SetPriAndPubKey(priky) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "set pri and pub key fauled!";
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        CLIENT_ERROR("init ecdh create secret key failed!");
        return "ecdh init failed!";
    }

    if (InitTransport() != kClientSuccess) {
        CLIENT_ERROR("InitTransport failed!");
        return "init transport failed!";
    }

    if (InitNetworkSingleton() != kClientSuccess) {
        CLIENT_ERROR("InitNetworkSingleton failed!");
        return "init network failed!";
    }

    if (priky.empty()) {
        std::string tx_gid;
        Transaction("", 0, tx_gid);
        std::cout << "tx gid: " << common::Encode::HexEncode(tx_gid) << std::endl;
        std::this_thread::sleep_for(std::chrono::microseconds(3000000ull));
        auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId);

        if (CheckTransaction(tx_gid) != "OK") {
            std::cout << "check transaction failed!" << std::endl;
            CLIENT_ERROR("check transaction failed!");
            return "check transaction failed: " + std::to_string(uni_dht->readonly_dht()->size());
        }
        return "create account success: " + std::to_string(uni_dht->readonly_dht()->size());
        std::cout << "create account success!" << std::endl;
    }
    return "OK";
}

std::string VpnClient::GetVpnServerNodes(
        const std::string& country,
        uint32_t count,
        std::vector<VpnServerNodePtr>& nodes) {
    auto uni_dht = std::dynamic_pointer_cast<network::Uniersal>(
            network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId));
    if (!uni_dht) {
        return "get universal dht error";
    }

    auto dht_nodes = uni_dht->RemoteGetNetworkNodes(
            network::kVpnNetworkId,
            common::global_country_map[country],
            count);
    std::cout << "get vpn nodes: " << dht_nodes.size() << std::endl;
    if (dht_nodes.empty()) {
        return "vpn nodes empty";
    }
    int res = GetVpnNodes(dht_nodes, nodes);
    if (res != kClientSuccess) {
        return "get vpn nodes failed!";
    }
    return "OK";
}

int VpnClient::GetVpnNodes(
        const std::vector<dht::NodePtr>& nodes,
        std::vector<VpnServerNodePtr>& vpn_nodes) {
    uint32_t msg_id = common::GlobalInfo::Instance()->MessageId();
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        transport::protobuf::Header msg;
        ClientProto::CreateGetVpnInfoRequest(root_dht_->local_node(), nodes[i], msg_id, msg);
        root_dht_->transport()->Send(nodes[i]->public_ip, nodes[i]->public_port, 0, msg);
    }

    common::StateLock state_lock(0);
    std::mutex re_mutex;
    std::atomic<uint32_t> res_num{ 0 };
    uint32_t expect_num = nodes.size();
    auto callback = [&state_lock, &vpn_nodes, &re_mutex, &res_num, expect_num](
            int status,
            transport::protobuf::Header& header) {
        do  {
            if (status != transport::kTransportSuccess) {
                break;
            }

            if (header.type() != common::kServiceMessage) {
                break;
            }

            protobuf::ServiceMessage svr_msg;
            if (!svr_msg.ParseFromString(header.data())) {
                break;
            }

            if (!svr_msg.has_vpn_res()) {
                break;
            }

            if (svr_msg.vpn_res().ip().empty() ||
                    svr_msg.vpn_res().port() <= 0 ||
                    svr_msg.vpn_res().encrypt_type().empty() ||
                    svr_msg.vpn_res().passwd().empty()) {
                break;
            }

            security::PublicKey pubkey;
            if (pubkey.Deserialize(svr_msg.vpn_res().pubkey()) != 0) {
                break;
            }
            // ecdh encrypt vpn password
            std::string sec_key;
            auto res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key);
            if (res != security::kSecuritySuccess) {
                CLIENT_ERROR("create sec key failed!");
                return;
            }

            std::string dec_passwd;
            if (security::Aes::Decrypt(
                    svr_msg.vpn_res().passwd(),
                    sec_key,
                    dec_passwd) != security::kSecuritySuccess) {
                CLIENT_ERROR("aes encrypt failed!");
                return;
            }
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("called", header);
            std::lock_guard<std::mutex> guard(re_mutex);
            vpn_nodes.push_back(std::make_shared<VpnServerNode>(
                    svr_msg.vpn_res().ip(),
                    svr_msg.vpn_res().port(),
                    svr_msg.vpn_res().encrypt_type(),
                    dec_passwd));
        } while (0);
        ++res_num;
        if (res_num >= expect_num) {
            state_lock.Signal();
        }
    };
    std::cout << "add to sync wait now: " << msg_id << std::endl;
    transport::SynchroWait::Instance()->Add(msg_id, 500 * 1000, callback, nodes.size());
    state_lock.Wait();
    return kClientSuccess;
}

int VpnClient::InitTransport() {
    transport_ = std::make_shared<transport::UdpTransport>(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            send_buff_size_,
            recv_buff_size_);
    transport::MultiThreadHandler::Instance()->Init(transport_);
    if (transport_->Init() != transport::kTransportSuccess) {
        CLIENT_ERROR("init udp transport failed!");
        return kClientError;
    }

    if (transport_->Start(false) != transport::kTransportSuccess) {
        CLIENT_ERROR("start udp transport failed!");
        return kClientError;
    }
    return kClientSuccess;
}

int VpnClient::SetPriAndPubKey(const std::string& prikey) {
    std::shared_ptr<security::PrivateKey> prikey_ptr{ nullptr };
    if (!prikey.empty()) {
        security::PrivateKey private_key(prikey);
        prikey_ptr = std::make_shared<security::PrivateKey>(private_key);
    }
    else {
        security::PrivateKey private_key;
        prikey_ptr = std::make_shared<security::PrivateKey>(private_key);
    }
    security::PublicKey pubkey(*(prikey_ptr.get()));
    auto pubkey_ptr = std::make_shared<security::PublicKey>(pubkey);
    security::Schnorr::Instance()->set_prikey(prikey_ptr);
    security::Schnorr::Instance()->set_pubkey(pubkey_ptr);

    std::string pubkey_str;
    pubkey.Serialize(pubkey_str);
    std::string account_id = common::Hash::Hash256(pubkey_str);
    common::GlobalInfo::Instance()->set_id(account_id);
    return kClientSuccess;
}

int VpnClient::InitNetworkSingleton() {
    if (network::Bootstrap::Instance()->Init(config) != network::kNetworkSuccess) {
        CLIENT_ERROR("init bootstrap failed!");
        return kClientError;
    }

    network::DhtManager::Instance()->Init();
    network::UniversalManager::Instance()->Init();
    network::Route::Instance()->Init();
    if (network::UniversalManager::Instance()->CreateUniversalNetwork(
            config,
            transport_) != network::kNetworkSuccess) {
        CLIENT_ERROR("create universal network failed!");
        return kClientError;
    }
    return kClientSuccess;
    return CreateClientUniversalNetwork();
}

int VpnClient::CreateClientUniversalNetwork() {
    return kClientSuccess;
    dht::DhtKeyManager dht_key(
            network::kVpnNetworkId,
            common::GlobalInfo::Instance()->country(),
            common::GlobalInfo::Instance()->id());
    dht::NodePtr local_node = std::make_shared<dht::Node>(
            common::GlobalInfo::Instance()->id(),
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            client_mode_,
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            security::Schnorr::Instance()->pubkey());
    NETWORK_INFO("create universal network[%s][%d][%s]",
            common::GlobalInfo::Instance()->id().c_str(),
            common::GlobalInfo::Instance()->id().size(),
            common::Encode::HexEncode(dht_key.StrKey()).c_str());
    local_node->first_node = common::GlobalInfo::Instance()->config_first_node();
    root_dht_ = std::make_shared<ClientUniversalDht>(transport_, local_node);
    root_dht_->Init();
    auto base_dht = std::dynamic_pointer_cast<dht::BaseDht>(root_dht_);
    network::DhtManager::Instance()->RegisterDht(network::kVpnNetworkId, base_dht);

    auto boot_nodes = network::Bootstrap::Instance()->GetNetworkBootstrap(network::kVpnNetworkId, 3);
    std::cout << "boot nodes: " << boot_nodes.size() << std::endl;
    if (boot_nodes.empty()) {
        return kClientError;
    }

    if (root_dht_->Bootstrap(boot_nodes) != dht::kDhtSuccess) {
        NETWORK_ERROR("join universal network failed!");
        return kClientError;
    }
    return kClientSuccess;
}

std::string VpnClient::Transaction(const std::string& to, uint64_t amount, std::string& tx_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
    tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    ClientProto::CreateTxRequest(
            uni_dht->local_node(),
            tx_gid,
            to,
            amount,
            rand_num,
            msg);
    network::Route::Instance()->Send(msg);
    return "OK";
}

std::string VpnClient::CheckTransaction(const std::string& tx_gid) {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    ClientProto::GetBlockWithTxGid(uni_dht->local_node(), tx_gid, true, msg);
    uni_dht->SendToClosestNode(msg);

    common::StateLock state_lock(0);
    bool block_finded = false;
    auto callback = [&state_lock, &block_finded](
        int status,
        transport::protobuf::Header& header) {
        do {
            if (status != transport::kTransportSuccess) {
                break;
            }

            if (header.type() != common::kBlockMessage) {
                break;
            }
            protobuf::BlockMessage block_msg;
            if (!block_msg.ParseFromString(header.data())) {
                break;
            }

            if (block_msg.block_res().block().empty()) {
                break;
            }
            block_finded = true;
        } while (0);
        state_lock.Signal();
    };
    transport::SynchroWait::Instance()->Add(msg.id(), 1 * 1000 * 1000, callback, 1);
    state_lock.Wait();
    if (!block_finded) {
        return "ERROR";
    }
    return "OK";
}

}  // namespace client

}  // namespace lego
