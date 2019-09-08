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
#include "common/tick.h"
#include "common/string_utils.h"
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
static common::Tick check_tx_tick_;
static common::Tick vpn_nodes_tick_;
static common::Tick dump_comfig_tick_;
static common::Tick dump_bootstrap_tick_;

VpnClient::VpnClient() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    check_tx_tick_.CutOff(1000 * 1000, std::bind(&VpnClient::CheckTxExists, this));
    vpn_nodes_tick_.CutOff(1000 * 1000, std::bind(&VpnClient::GetVpnNodes, this));
    dump_comfig_tick_.CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpVpnNodes, this));
    dump_bootstrap_tick_.CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpBootstrapNodes, this));
}

VpnClient::~VpnClient() {}

VpnClient* VpnClient::Instance() {
    static VpnClient ins;
    return &ins;
}

void VpnClient::HandleMessage(transport::protobuf::Header& header) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("client end", header);
    if (header.type() == common::kServiceMessage) {
        HandleServiceMessage(header);
    }

    if (header.type() == common::kBlockMessage) {
        HandleBlockMessage(header);
    }
}

void VpnClient::HandleBlockMessage(transport::protobuf::Header& header) {
    protobuf::BlockMessage block_msg;
    if (!block_msg.ParseFromString(header.data())) {
        return;
    }

    if (block_msg.has_height_res()) {
        HandleHeightResponse(block_msg.height_res());
    }

    if (block_msg.has_block_res()) {
        HandleBlockResponse(block_msg.block_res());
    }
}

void VpnClient::HandleBlockResponse(const protobuf::GetTxBlockResponse& block_res) {
    protobuf::Block block;
    if (!block.ParseFromString(block_res.block())) {
        return;
    }
    std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
    hight_block_map_[block.height()] = block_res.block();
    if (hight_block_map_.size() >= kHeightMaxSize) {
        hight_block_map_.erase(hight_block_map_.begin());
    }
    got_block_ = true;
}

void VpnClient::HandleHeightResponse(
        const protobuf::AccountHeightResponse& height_res) {
    std::lock_guard<std::mutex> guard(height_set_mutex_);
    for (int32_t i = 0; i < height_res.heights_size(); ++i) {
        height_set_.insert(height_res.heights(i));
        if (height_set_.size() > kHeightMaxSize) {
            height_set_.erase(height_set_.begin());
        }
    }
}

void VpnClient::HandleServiceMessage(transport::protobuf::Header& header) {
    protobuf::ServiceMessage svr_msg;
    if (!svr_msg.ParseFromString(header.data())) {
        return;
    }

    if (svr_msg.has_vpn_res()) {
        HandleGetVpnResponse(
                svr_msg.vpn_res(),
                common::Encode::HexEncode(header.src_dht_key()));
    }
}

void VpnClient::HandleGetVpnResponse(
        const protobuf::GetVpnInfoResponse& vpn_res,
        const std::string& dht_key) {
    if (vpn_res.ip().empty() ||
            vpn_res.country().empty() ||
            vpn_res.pubkey().empty()) {
        return;
    }

    security::PublicKey pubkey;
    if (pubkey.Deserialize(vpn_res.pubkey()) != 0) {
        return;
    }
    // ecdh encrypt vpn password
    std::string sec_key;
    auto res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key);
    if (res != security::kSecuritySuccess) {
        CLIENT_ERROR("create sec key failed!");
        return;
    }

    auto node_ptr = std::make_shared<VpnServerNode>(
            vpn_res.ip(),
            vpn_res.svr_port(),
            vpn_res.route_port(),
            common::Encode::HexEncode(sec_key),
            dht_key,
            common::Encode::HexEncode(vpn_res.pubkey()),
            true);
    if (vpn_res.svr_port() > 0) {
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        auto iter = vpn_nodes_map_.find(vpn_res.country());
        if (iter != vpn_nodes_map_.end()) {
            auto e_iter = std::find_if(
                    iter->second.begin(),
                    iter->second.end(),
                    [node_ptr](const VpnServerNodePtr& ptr) {
                        return node_ptr->dht_key == ptr->dht_key;
                    });
            if (e_iter == iter->second.end()) {
                iter->second.push_back(node_ptr);
                if (iter->second.size() > 16) {
                    iter->second.pop_front();
                }
            }
        }
    }

    if (vpn_res.route_port() > 0) {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        auto iter = route_nodes_map_.find(vpn_res.country());
        if (iter != route_nodes_map_.end()) {
            auto e_iter = std::find_if(
                iter->second.begin(),
                iter->second.end(),
                [node_ptr](const VpnServerNodePtr& ptr) {
                return node_ptr->dht_key == ptr->dht_key;
            });
            if (e_iter == iter->second.end()) {
                iter->second.push_back(node_ptr);
                if (iter->second.size() > 16) {
                    iter->second.pop_front();
                }
            }
        }
    }
}

void VpnClient::VpnHeartbeat(const std::string& dht_key) {
    transport::protobuf::Header msg;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    ClientProto::CreateVpnHeartbeat(
            root_dht_->local_node(),
            common::Encode::HexDecode(dht_key),
            msg);
    uni_dht->SendToClosestNode(msg);
}

int VpnClient::GetSocket() {
    return transport_->GetSocket();
}

int64_t VpnClient::GetBalance() {
    std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
    if (hight_block_map_.empty()) {
        return -1;
    }
    protobuf::Block block;
    auto iter = hight_block_map_.rbegin();
    if (!block.ParseFromString(iter->second)) {
        return -1;
    }

    auto tx_list = block.tx_block().tx_list();
    for (int32_t i = tx_list.size() - 1; i >= 0; --i) {
        if (tx_list[i].to().empty()) {
            continue;
        }

        if (tx_list[i].to() != common::GlobalInfo::Instance()->id() &&
            tx_list[i].from() != common::GlobalInfo::Instance()->id()) {
            continue;
        }

        return tx_list[i].balance();
    }
    return -1;
}

std::string VpnClient::Transactions(uint32_t begin, uint32_t len) {
    std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
    uint32_t now_b = 0;
    uint32_t now_len = 0;
    std::string res_str;
    for (auto iter = hight_block_map_.rbegin(); iter != hight_block_map_.rend(); ++iter) {
        if (now_b < begin) {
            ++now_b;
            continue;
        }
        protobuf::Block block;
        if (!block.ParseFromString(iter->second)) {
            continue;
        }
        
        auto tx_list = block.tx_block().tx_list();
        auto timestamp = common::MicTimestampToDatetime(block.timestamp());
        for (int32_t i = 0; i < tx_list.size(); ++i) {
            if (tx_list[i].to().empty()) {
                continue;
            }

            if (tx_list[i].to() != common::GlobalInfo::Instance()->id() &&
                    tx_list[i].from() != common::GlobalInfo::Instance()->id()) {
                continue;
            }

            std::string tx_item;
            if (tx_list[i].from() == common::GlobalInfo::Instance()->id()) {
                tx_item = (timestamp + ",TRAN" + "," +
                        common::Encode::HexEncode(tx_list[i].to()) + ",");
                tx_item += "-" + std::to_string(tx_list[i].amount());
            } else {
                tx_item = (timestamp + ",TRAN" + "," +
                        common::Encode::HexEncode(tx_list[i].from()) + ",");
                tx_item += std::to_string(tx_list[i].amount());
            }

            if (res_str.empty()) {
                res_str = tx_item;
            } else {
                res_str += ";" + tx_item;
            }
        }
        ++now_len;
        if (now_len >= len) {
            break;
        }
    }
    return res_str;
}

std::string VpnClient::Init(
        const std::string& local_ip,
        uint16_t local_port,
        const std::string& bootstrap,
        const std::string& conf_path,
        const std::string& log_path,
        const std::string& log_conf_path) {
    WriteDefaultLogConf(log_conf_path, log_path);
    log4cpp::PropertyConfigurator::configure(log_conf_path);
    std::string private_key;
    config_path_ = conf_path;
    if (ConfigExists(conf_path)) {
        if (!config.Init(conf_path)) {
            CLIENT_ERROR("init config failed!");
            return "ERROR";
        }

        std::string priky("");
        if (!config.Get("lego", "prikey", priky) || priky.empty()) {
            CLIENT_ERROR("config[%s] invalid!", conf_path.c_str());
        } else {
            private_key = common::Encode::HexDecode(priky);
        }
    }

    ReadVpnNodesFromConf();
    config.Get("lego", "first_instasll", first_install_);
    config.Set("lego", "local_ip", local_ip);
    config.Set("lego", "local_port", local_port);
    config.Set("lego", "country", std::string("CN"));
    config.Set("lego", "first_node", false);
    config.Set("lego", "client", true);
    config.Set("lego", "bootstrap", bootstrap);
    config.Set("lego", "id", std::string("test_id"));
    std::string boot_net;
    config.Get("lego", "bootstrap_net", boot_net);
    boot_net += "," + bootstrap;
    if (common::GlobalInfo::Instance()->Init(config) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return "ERROR";
    }

    if (SetPriAndPubKey(private_key) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "ERROR";
    }

    config.Set("lego", "prikey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_prikey()));
    config.Set("lego", "pubkey", common::Encode::HexEncode(
            security::Schnorr::Instance()->str_pubkey()));
    std::string account_address = network::GetAccountAddressByPublicKey(
            security::Schnorr::Instance()->str_pubkey());
    common::GlobalInfo::Instance()->set_id(account_address);
    config.Set("lego", "id", common::Encode::HexEncode(
            common::GlobalInfo::Instance()->id()));
    config.DumpConfig(conf_path);

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        CLIENT_ERROR("init ecdh create secret key failed!");
        return "ERROR";
    }

    if (InitTransport() != kClientSuccess) {
        CLIENT_ERROR("InitTransport failed!");
        return "ERROR";
    }

    if (InitNetworkSingleton() != kClientSuccess) {
        CLIENT_ERROR("InitNetworkSingleton failed!");
        return "ERROR";
    }
    return (common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) +
            "," +
            common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()));
}

std::string VpnClient::GetPublicKey() {
    return common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey());
}

std::string VpnClient::GetSecretKey(const std::string& peer_pubkey) {
    std::string sec_key;
    security::PublicKey pubkey(peer_pubkey);
    if (security::EcdhCreateKey::Instance()->CreateKey(
            pubkey,
            sec_key) != security::kSecuritySuccess) {
        return "ERROR";
    }

    return common::Encode::HexEncode(sec_key);
}

std::string VpnClient::EncryptData(const std::string& seckey, const std::string& data) {
    std::string enc_out;
    if (security::Aes::Encrypt(data, seckey, enc_out) != security::kSecuritySuccess) {
        return "ERROR";
    }
    return common::Encode::HexEncode(enc_out);
}

std::string VpnClient::DecryptData(const std::string& seckey, const std::string& data) {
    std::string dec_out;
    if (security::Aes::Decrypt(data, seckey, dec_out) != security::kSecuritySuccess) {
        return "ERROR";
    }
    return common::Encode::HexEncode(dec_out);
}

bool VpnClient::SetFirstInstall() {
    first_install_ = true;
    config.Set("lego", "first_instasll", first_install_);
    config.DumpConfig(config_path_);
    return true;
}

bool VpnClient::ConfigExists(const std::string& conf_path) {
    FILE* file = NULL;
    file = fopen(conf_path.c_str(), "r");
    if (file == NULL) {
        return false;
    }

    struct stat buf;
    int fd = fileno(file);
    fstat(fd, &buf);
    fclose(file);
    if (buf.st_size <= 0) {
        return false;
    }
    return true;
}

void VpnClient::WriteDefaultLogConf(
        const std::string& log_conf_path,
        const std::string& log_path) {
    FILE* file = NULL;
    file = fopen(log_conf_path.c_str(), "w");
    if (file == NULL) {
        return;
    }
    std::string log_str = ("# log4cpp.properties\n"
        "log4cpp.rootCategory = WARN\n"
        "log4cpp.category.sub1 = WARN, programLog\n"
        "log4cpp.appender.rootAppender = ConsoleAppender\n"
        "log4cpp.appender.rootAppender.layout = PatternLayout\n"
        "log4cpp.appender.rootAppender.layout.ConversionPattern = %d [%p] %m%n\n"
        "log4cpp.appender.programLog = RollingFileAppender\n"
        "log4cpp.appender.programLog.fileName = ") + log_path + "\n" +
        std::string("log4cpp.appender.programLog.maxFileSize = 1073741824\n"
        "log4cpp.appender.programLog.maxBackupIndex = 1\n"
        "log4cpp.appender.programLog.layout = PatternLayout\n"
        "log4cpp.appender.programLog.layout.ConversionPattern = %d [%p] %m%n\n");
    fwrite(log_str.c_str(), log_str.size(), 1, file);
    fclose(file);
}

std::string VpnClient::GetTransactionInfo(const std::string& tx_gid) {
    auto tmp_gid = common::Encode::HexDecode(tx_gid);
    std::lock_guard<std::mutex> guard(tx_map_mutex_);
    auto iter = tx_map_.find(tmp_gid);
    if (iter != tx_map_.end()) {
        if (iter->second == nullptr) {
            return "";
        }

        std::string tmp_str = iter->second->to + "\t" +
                std::to_string(iter->second->balance) + "\t" +
                std::to_string(iter->second->height) + "\t" +
                iter->second->block_hash + "\t" +
                tx_gid;
        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        CLIENT_ERROR("get transaction info success[%s]", tx_gid.c_str());
        return tmp_str;
    } else {
        tx_map_[tmp_gid] = nullptr;
    }
    return "";
}

std::string VpnClient::GetVpnServerNodes(
        const std::string& country,
        uint32_t count,
        bool route,
        std::vector<VpnServerNodePtr>& nodes) {
    if (!route) {
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        auto iter = vpn_nodes_map_.find(country);
        if (iter == vpn_nodes_map_.end()) {
            vpn_nodes_map_[country] = std::deque<VpnServerNodePtr>();
            std::vector<std::string> ct_vec = { country };
        } else {
            for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
                nodes.push_back(*qiter);
            }

            if (nodes.empty()) {
                return "get vpn nodes failed!";
            }
            return "OK";
        }
    } else {
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        auto iter = route_nodes_map_.find(country);
        if (iter == route_nodes_map_.end()) {
            route_nodes_map_[country] = std::deque<VpnServerNodePtr>();
            std::vector<std::string> ct_vec = { country };
        } else {
            for (auto qiter = iter->second.begin(); qiter != iter->second.end(); ++qiter) {
                nodes.push_back(*qiter);
            }

            if (nodes.empty()) {
                return "get vpn nodes failed!";
            }
            return "OK";
        }
    }

    return "get vpn nodes failed!";
}

void VpnClient::GetVpnNodes() {
    std::vector<std::string> country_vec;
    {
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        for (auto iter = vpn_nodes_map_.begin(); iter != vpn_nodes_map_.end(); ++iter) {
            country_vec.push_back(iter->first);
        }
    }

    GetNetworkNodes(country_vec, network::kVpnNetworkId);
    {
        country_vec.clear();
        std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
        for (auto iter = route_nodes_map_.begin(); iter != route_nodes_map_.end(); ++iter) {
            country_vec.push_back(iter->first);
        }
    }

    GetNetworkNodes(country_vec, network::kVpnRouteNetworkId);
    vpn_nodes_tick_.CutOff(kGetVpnNodesPeriod, std::bind(&VpnClient::GetVpnNodes, this));
}

void VpnClient::GetNetworkNodes(
        const std::vector<std::string>& country_vec,
        uint32_t network_id) {
    for (uint32_t i = 0; i < country_vec.size(); ++i) {
        auto country = country_vec[i];
        auto uni_dht = std::dynamic_pointer_cast<network::Uniersal>(
            network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId));
        if (!uni_dht) {
            continue;
        }

        auto dht_nodes = uni_dht->RemoteGetNetworkNodes(
                network_id,
                common::global_country_map[country],
                4);
        if (dht_nodes.empty()) {
            continue;
        }
        uint32_t msg_id = common::GlobalInfo::Instance()->MessageId();
        for (uint32_t i = 0; i < dht_nodes.size(); ++i) {
            transport::protobuf::Header msg;
            auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
                    network::kUniversalNetworkId);
            ClientProto::CreateGetVpnInfoRequest(
                    root_dht_->local_node(),
                    dht_nodes[i],
                    msg_id,
                    msg);
            uni_dht->SendToClosestNode(msg);
            CLIENT_ERROR("get dht_nodes from[%s][%d]",
                dht_nodes[i]->public_ip.c_str(), dht_nodes[i]->public_port);
        }
    }
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

int VpnClient::ResetTransport(const std::string& ip, uint16_t port) {
    transport::TransportPtr tmp_udp_transport = std::make_shared<transport::UdpTransport>(
            ip,
            port,
            send_buff_size_,
            recv_buff_size_);
    if (tmp_udp_transport->Init() != transport::kTransportSuccess) {
        CLIENT_ERROR("init udp transport failed!");
        return -1;
    }

    if (tmp_udp_transport->Start(false) != transport::kTransportSuccess) {
        CLIENT_ERROR("start udp transport failed!");
        return -1;
    }
    transport::MultiThreadHandler::Instance()->ResetTransport(tmp_udp_transport);
    common::GlobalInfo::Instance()->set_config_local_ip(ip);
    common::GlobalInfo::Instance()->set_config_local_port(port);
    transport_ = tmp_udp_transport;
    return tmp_udp_transport->GetSocket();
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

    CLIENT_INFO("new prikey[%s]", common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()).c_str());
    CLIENT_INFO("new pubkey[%s]", common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey()).c_str());

    std::string pubkey_str;
    pubkey.Serialize(pubkey_str);
    std::string account_id = network::GetAccountAddressByPublicKey(pubkey_str);
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
    return CreateClientUniversalNetwork();
}

int VpnClient::CreateClientUniversalNetwork() {
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
    NETWORK_ERROR("create universal network[%s][%d][%s]",
            common::GlobalInfo::Instance()->id().c_str(),
            common::GlobalInfo::Instance()->id().size(),
            common::Encode::HexEncode(dht_key.StrKey()).c_str());
    local_node->first_node = common::GlobalInfo::Instance()->config_first_node();
    root_dht_ = std::make_shared<ClientUniversalDht>(transport_, local_node);
    root_dht_->Init();
    auto base_dht = std::dynamic_pointer_cast<dht::BaseDht>(root_dht_);
    network::DhtManager::Instance()->RegisterDht(network::kVpnNetworkId, base_dht);
    return kClientSuccess;
}

std::string VpnClient::Transaction(const std::string& to, uint64_t amount, std::string& tx_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return "ERROR";
    }
    tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    std::string to_addr;
    if (!to.empty()) {
        to_addr = common::Encode::HexDecode(to);
    }

    ClientProto::CreateTxRequest(
            uni_dht->local_node(),
            tx_gid,
            to_addr,
            amount,
            rand_num,
            msg);
    network::Route::Instance()->Send(msg);
    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        tx_map_.insert(std::make_pair(tx_gid, nullptr));
    }
    tx_gid = common::Encode::HexEncode(tx_gid);
    CLIENT_ERROR("send new tx: %s, from: %s, to: %s, amount: %llu",
            tx_gid.c_str(),
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()).c_str(),
            to.c_str(),
            amount);
    return "OK";
}

void VpnClient::CheckTxExists() {
    {
        if (!root_dht_joined_) {
            auto boot_nodes = network::Bootstrap::Instance()->GetNetworkBootstrap(
                    network::kVpnNetworkId,
                    3);
            if (!boot_nodes.empty()) {
                if (root_dht_->Bootstrap(boot_nodes) == dht::kDhtSuccess) {
                    root_dht_joined_ = true;
                }
            }
        }
    }

    GetAccountHeight();
    GetAccountBlockWithHeight();
    check_tx_tick_.CutOff(kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
}

TxInfoPtr VpnClient::GetBlockWithGid(const std::string& tx_gid) {
    auto tmp_gid = common::Encode::HexDecode(tx_gid);
    std::lock_guard<std::mutex> guard(tx_map_mutex_);
    auto iter = tx_map_.find(tmp_gid);
    if (iter != tx_map_.end()) {
        if (iter->second == nullptr) {
            return nullptr;
        }

        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        return tmp_ptr;
    } else {
        tx_map_[tmp_gid] = nullptr;
    }
    return nullptr;
}

TxInfoPtr VpnClient::GetBlockWithHash(const std::string& block_hash) {
    auto tmp_gid = std::string("b_") + common::Encode::HexDecode(block_hash);
    std::lock_guard<std::mutex> guard(tx_map_mutex_);
    auto iter = tx_map_.find(tmp_gid);
    if (iter != tx_map_.end()) {
        if (iter->second == nullptr) {
            return nullptr;
        }

        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        return tmp_ptr;
    } else {
        tx_map_[tmp_gid] = nullptr;
    }
    return nullptr;

}

void VpnClient::GetAccountHeight() {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }
    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    ClientProto::GetAccountHeight(uni_dht->local_node(), msg);
    uni_dht->SendToClosestNode(msg);
}

void VpnClient::GetAccountBlockWithHeight() {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }

    std::set<uint64_t> height_set;
    {
        std::lock_guard<std::mutex> guard(height_set_mutex_);
        height_set = height_set_;
    }

    uint32_t sended_req = 0;
    for (auto iter = height_set.rbegin(); iter != height_set.rend(); ++iter) {
        auto height = *iter;
        {
            auto iter = hight_block_map_.find(height);
            if (iter != hight_block_map_.end()) {
                continue;
            }
        }
        transport::protobuf::Header msg;
        uni_dht->SetFrequently(msg);
        ClientProto::GetBlockWithHeight(uni_dht->local_node(), height, msg);
        uni_dht->SendToClosestNode(msg);
        ++sended_req;
        if (sended_req > 30) {
            break;
        }
    }
}

void VpnClient::DumpVpnNodes() {
    std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    std::string country_list;
    for (auto iter = vpn_nodes_map_.begin(); iter != vpn_nodes_map_.end(); ++iter) {
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->svr_port));
            conf_str += tmp_str + ";";
        }
        config.Set("vpn", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("vpn", "country", country_list);
    config.DumpConfig(config_path_);
    dump_comfig_tick_.CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpVpnNodes, this));
}

void VpnClient::ReadVpnNodesFromConf() {
    std::string country_list;
    config.Get("vpn", "country", country_list);
    if (country_list.empty()) {
        return;
    }

    common::Split country_split(country_list.c_str(), ',', country_list.size());
    for (uint32_t i = 0; i < country_split.Count(); ++i) {
        if (country_split.SubLen(i) <= 1) {
            continue;
        }

        std::string vpn_nodes;
        config.Get("vpn", country_split[i], vpn_nodes);
        if (vpn_nodes.empty()) {
            continue;
        }

        common::Split node_list(vpn_nodes.c_str(), ';', vpn_nodes.size());
        for (uint32_t node_idx = 0; node_idx < node_list.Count(); ++node_idx) {
            if (node_list.SubLen(node_idx) <= 10) {
                continue;
            }

            common::Split item_split(node_list[node_idx], ',', node_list.SubLen(node_idx));
            if (item_split.Count() < 5) {
                continue;
            }

            auto node_item = std::make_shared<VpnServerNode>(
                    item_split[3],
                    common::StringUtil::ToUint16(item_split[4]),
                    0,
                    item_split[1],
                    item_split[0],
                    item_split[2],
                    false);
            std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
            auto iter = vpn_nodes_map_.find(country_split[i]);
            if (iter == vpn_nodes_map_.end()) {
                vpn_nodes_map_[country_split[i]] = std::deque<VpnServerNodePtr>();
                vpn_nodes_map_[country_split[i]].push_back(node_item);
                continue;
            }
                
            iter->second.push_back(node_item);
            if (iter->second.size() > 16) {
                iter->second.pop_front();
            }
        }
    }
}

void VpnClient::DumpBootstrapNodes() {
    auto dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    auto dht_nodes = dht->readonly_dht();
    std::unordered_set<std::string> bootstrap_set;
    for (auto iter = dht_nodes->begin(); iter != dht_nodes->end(); ++iter) {
        std::string node_info = ("id:" +
                (*iter)->public_ip + ":" +
                std::to_string((*iter)->public_port));
        auto siter = bootstrap_set.find(node_info);
        if (siter != bootstrap_set.end()) {
            continue;
        }
        bootstrap_set.insert(node_info);
    }

    if (!bootstrap_set.empty()) {
        std::string boot_str;
        for (auto iter = bootstrap_set.begin(); iter != bootstrap_set.end(); ++iter) {
            boot_str += *iter + ",";
        }
        config.Set("lego", "bootstrap_net", boot_str);
        config.DumpConfig(config_path_);
    }

    dump_bootstrap_tick_.CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpBootstrapNodes, this));
}

}  // namespace client

}  // namespace lego
