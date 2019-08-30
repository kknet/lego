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

VpnClient::VpnClient() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    check_tx_tick_.CutOff(kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
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
}

void VpnClient::HandleHeightResponse(
        const protobuf::AccountHeightResponse& height_res) {
    std::lock_guard<std::mutex> guard(height_queue_mutex_);
    for (int32_t i = 0; i < height_res.heights_size(); ++i) {
        height_queue_.push(height_res.heights(i));
        if (height_queue_.size() > kHeightMaxSize) {
            height_queue_.pop();
        }
    }
}

void VpnClient::HandleServiceMessage(transport::protobuf::Header& header) {
    transport::SynchroWait::Instance()->Callback(header.id(), header);
}

int VpnClient::GetSocket() {
    return transport_->GetSocket();
}

std::string VpnClient::Init(const std::string& conf) {
    if (!config.Init(conf)) {
        CLIENT_ERROR("init config[%s] failed!", conf.c_str());
        return "init config failed";
    }

    if (common::GlobalInfo::Instance()->Init(config) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return "init global failed";
    }

    std::string priky("");
    if (!config.Get("lego", "prikey", priky) || priky.empty()) {
        CLIENT_ERROR("config[%s] invalid!", conf.c_str());
        return "config invalid";
    }

    std::string private_key = common::Encode::HexDecode(priky);
    if (SetPriAndPubKey(private_key) != kClientSuccess) {
        CLIENT_ERROR("SetPriAndPubKey failed!");
        return "set private and pub key failed!";
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
    return "OK";
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

    config.Get("lego", "first_instasll", first_install_);
    config.Set("lego", "local_ip", local_ip);
    config.Set("lego", "local_port", local_port);
    config.Set("lego", "country", std::string("CN"));
    config.Set("lego", "first_node", false);
    config.Set("lego", "client", true);
    config.Set("lego", "id", std::string("test_id"));
    config.Set("lego", "bootstrap", bootstrap);
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

bool VpnClient::SetFirstInstall() {
    first_install_ = true;
    config.Set("lego", "first_instasll", first_install_);
    config.DumpConfig(config_path_);
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
        "log4cpp.rootCategory = DEBUG\n"
        "log4cpp.category.sub1 = DEBUG, programLog\n"
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
        std::vector<VpnServerNodePtr>& nodes) {
    auto uni_dht = std::dynamic_pointer_cast<network::Uniersal>(
            network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId));
    if (!uni_dht) {
        return "get universal dht error";
    }

    std::vector<dht::NodePtr> dht_nodes = uni_dht->LocalGetNetworkNodes(
            network::kVpnNetworkId,
            common::global_country_map[country],
            count);
    if (dht_nodes.empty()) {
        dht_nodes = uni_dht->RemoteGetNetworkNodes(
                network::kVpnNetworkId,
                common::global_country_map[country],
                count);
    }
    std::cout << "get vpn nodes: " << dht_nodes.size() << std::endl;
    CLIENT_ERROR("get dht_nodes: [%d]", dht_nodes.size());
    if (dht_nodes.empty()) {
        CLIENT_ERROR("get dht_nodes: vpn nodes empty!");
        return "vpn nodes empty";
    }
    int res = GetVpnNodes(dht_nodes, nodes);
    if (res != kClientSuccess) {
        CLIENT_ERROR("get dht_nodes: get vpn nodes failed!");
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
        auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId);
        ClientProto::CreateGetVpnInfoRequest(root_dht_->local_node(), nodes[i], msg_id, msg);
        uni_dht->SendToClosestNode(msg);
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
    transport::SynchroWait::Instance()->Add(msg_id, 1000 * 1000, callback, nodes.size());
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

    std::priority_queue<uint64_t> height_queue;
    {
        std::lock_guard<std::mutex> guard(height_queue_mutex_);
        height_queue = height_queue_;
    }

    uint32_t sended_req = 0;
    while (!height_queue.empty()) {
        auto height = height_queue.top();
        height_queue.pop();
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

}  // namespace client

}  // namespace lego
