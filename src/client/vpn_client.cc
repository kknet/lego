#include "client/client_universal_dht.h"
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
#include "common/time_utils.h"
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
static std::shared_ptr<ClientUniversalDht> root_dht_{ nullptr };
static const std::string kCheckVersionAccount = common::Encode::HexDecode(
		"e8a1ceb6b807a98a20e3aa10aa2199e47cbbed08c2540bd48aa3e1e72ba6bd99");
static const std::string kClientDownloadUrl = (
		"ios;1.0.3;https://www.pgyer.com/1U2f,"
		"android;1.0.3;https://www.pgyer.com/62Dg,"
		"windows;1.0.3;,"
		"mac;1.0.3;");

VpnClient::VpnClient() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
	vpn_download_url_ = kClientDownloadUrl;
	check_tx_tick_ = std::make_shared<common::Tick>();
	vpn_nodes_tick_ = std::make_shared<common::Tick>();
	dump_config_tick_ = std::make_shared<common::Tick>();
	dump_bootstrap_tick_ = std::make_shared<common::Tick>();

}

VpnClient::~VpnClient() {}

VpnClient* VpnClient::Instance() {
    static VpnClient ins;
    return &ins;
}

std::string VpnClient::CheckVersion() {
	return vpn_download_url_;
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

	bool has_local_trans = false;
    std::lock_guard<std::mutex> guard(hight_block_map_mutex_);
    auto block_ptr = std::make_shared<protobuf::Block>(block);
    std::lock_guard<std::mutex> tmp_map_guard(tx_map_mutex_);
    auto& tx_list = block_ptr->tx_block().tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        tx_map_[tx_list[i].gid()] = block_ptr;
		if (tx_list[i].from() == common::GlobalInfo::Instance()->id() ||
				tx_list[i].to() == common::GlobalInfo::Instance()->id()) {
			has_local_trans = true;
		}

		if (tx_list[i].from() == kCheckVersionAccount ||
				tx_list[i].to() == kCheckVersionAccount) {
			if (block_ptr->height() >= vpn_version_last_height_) {
				for (int attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
					if (tx_list[i].attr(attr_idx).key() == "tenon_vpn_url") {
						vpn_download_url_ = tx_list[i].attr(attr_idx).value();
					}
				}
			}
		}
    }

	if (has_local_trans) {
		hight_block_map_[block.height()] = block_res.block();
		if (hight_block_map_.size() >= kHeightMaxSize) {
			hight_block_map_.erase(hight_block_map_.begin());
		}
	}
}

void VpnClient::HandleHeightResponse(
        const protobuf::AccountHeightResponse& height_res) {
	if (height_res.account_addr() == kCheckVersionAccount) {
		bool get_version_block = false;
		for (int32_t i = 0; i < height_res.heights_size(); ++i) {
			if (height_res.heights(i) > vpn_version_last_height_) {
				vpn_version_last_height_ = height_res.heights(i);
				get_version_block = true;
			}
		}

		if (get_version_block) {
			transport::protobuf::Header msg;
			auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
				network::kUniversalNetworkId);
			if (uni_dht == nullptr) {
				return;
			}
			uni_dht->SetFrequently(msg);
			ClientProto::GetBlockWithHeight(
					uni_dht->local_node(),
					kCheckVersionAccount,
					vpn_version_last_height_,
					msg);
			uni_dht->SendToClosestNode(msg);
		}

		return;
	}

    std::lock_guard<std::mutex> guard(height_set_mutex_);
    for (int32_t i = 0; i < height_res.heights_size(); ++i) {
        local_account_height_set_.insert(height_res.heights(i));
        if (local_account_height_set_.size() > kHeightMaxSize) {
            local_account_height_set_.erase(local_account_height_set_.begin());
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
            common::Encode::HexEncode(network::GetAccountAddressByPublicKey(vpn_res.pubkey())),
            true);
    if (vpn_res.svr_port() > 0) {
        CLIENT_ERROR("get vpn node: %s:%d", node_ptr->ip.c_str(), node_ptr->svr_port);
        std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
        auto iter = vpn_nodes_map_.find(vpn_res.country());
        if (iter != vpn_nodes_map_.end()) {
            auto e_iter = std::find_if(
                    iter->second.begin(),
                    iter->second.end(),
                    [node_ptr](const VpnServerNodePtr& ptr) {
                        return node_ptr->ip == ptr->ip && node_ptr->svr_port == ptr->svr_port;
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
            config.Set("lego", "prikey", std::string(""));
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
    config.Set("lego", "country", std::string("US"));
    config.Set("lego", "first_node", false);
    config.Set("lego", "client", true);
    config.Set("lego", "bootstrap", bootstrap);
    config.Set("lego", "id", std::string("test_id"));
    std::string boot_net;
    config.Get("lego", "bootstrap_net", boot_net);
    boot_net += "," + bootstrap;
    std::cout << "bootstrap from : " << boot_net << std::endl;
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
    std::string vpn_us_nodes;
    config.Get("vpn", "US", vpn_us_nodes);
    if (vpn_us_nodes.size() < 128) {
        InitRouteAndVpnServer();
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        CLIENT_ERROR("init ecdh create secret key failed!");
        return "ERROR";
    }
    ReadVpnNodesFromConf();
    ReadRouteNodesFromConf();
    config.DumpConfig(conf_path);

    if (InitTransport() != kClientSuccess) {
        CLIENT_ERROR("InitTransport failed!");
        return "ERROR";
    }

    if (InitNetworkSingleton() != kClientSuccess) {
        CLIENT_ERROR("InitNetworkSingleton failed!");
        return "ERROR";
    }
    
    check_tx_tick_->CutOff(1000 * 1000, std::bind(&VpnClient::CheckTxExists, this));
    vpn_nodes_tick_->CutOff(1000 * 1000, std::bind(&VpnClient::GetVpnNodes, this));
    dump_config_tick_->CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpNodeToConfig, this));
    dump_bootstrap_tick_->CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpBootstrapNodes, this));

    return (common::global_code_to_country_map[common::GlobalInfo::Instance()->country()] +
            "," +
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) +
            "," +
            common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()));
}

void VpnClient::InitRouteAndVpnServer() {    
#ifdef IOS_PLATFORM
	config.Set("route", "country", std::string("AU,BR,CA,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
#else
	config.Set("route", "country", std::string("AU,BR,CA,CN,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
#endif
	config.Set("route", "country", std::string("AU,BR,CA,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
    config.Set("route", "US", std::string("0410000038000000b003e4aa1f9e0c023363b95b7ddaea8eda9231aaefcb44d2,45f82bb181f5df52f862a4145f6738c80431d149a9f159de1986a9ff911754a0,0255bef707a29dac0f8ab974f953f50f5c1edcc18f0c3f341f9e290940110679dc,98.126.31.159,51765;"));
    config.Set("route", "SG", std::string(""));
    config.Set("route", "IN", std::string(""));
    config.Set("route", "GB", std::string(""));
#ifndef IOS_PLATFORM
    config.Set("route", "CN", std::string("041000001a0000006818f2be83d3b3f769b851faccb507d88c61b5463392d9d7,d8a257aae5d9252d7777fa4810a0851d91be63e6ff841b6216e11c3f9485378c,0328f7304e186bd1624155e8c0d8ab54a2a8fba6a3d41762a47fbf1e9e10f72972,120.77.2.117,53301;041000001a00000023b167ff2bc4fa5765c345b4addbe0ff8b1abe5d0af010eb,6737effbd804e0a55d933df04014d1799a7fbd09c1ff7746d14695f4655e440d,035acb6ec65d1bd35224d3d64d4cd278fcbf80e4886522872b13b9de658b59e2cc,47.105.87.61,61446;041000001a00000005fe9d923c3742c249a9e6343b4a3bb2cae2b20fec6336da,9e0775fe90eda8295d9059e595a96c4016605fd360aa163c4b47231e0d1eea7d,02845ded25aa2a9cf29830e2fa49941067728653543a1a62f55f13fe966471a9cb,121.199.11.177,53641;"));
#endif
#ifdef IOS_PLATFORM
	config.Set("vpn", "country", std::string("AU,BR,CA,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
#else
	config.Set("vpn", "country", std::string("AU,BR,CA,CN,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
#endif
    config.Set("vpn", "US", std::string("0310000038000000b003e4aa1f9e0c023363b95b7ddaea8eda9231aaefcb44d2,45f82bb181f5df52f862a4145f6738c80431d149a9f159de1986a9ff911754a0,0255bef707a29dac0f8ab974f953f50f5c1edcc18f0c3f341f9e290940110679dc,98.126.31.159,18182,1572062883888;"));
    config.Set("vpn", "IN", std::string(""));
    config.Set("vpn", "GB", std::string(""));
#ifndef IOS_PLATFORM
    config.Set("vpn", "CN", std::string("031000001a00000023b167ff2bc4fa5765c345b4addbe0ff8b1abe5d0af010eb,6737effbd804e0a55d933df04014d1799a7fbd09c1ff7746d14695f4655e440d,035acb6ec65d1bd35224d3d64d4cd278fcbf80e4886522872b13b9de658b59e2cc,47.105.87.61,16084,1572062883888;031000001a00000005fe9d923c3742c249a9e6343b4a3bb2cae2b20fec6336da,9e0775fe90eda8295d9059e595a96c4016605fd360aa163c4b47231e0d1eea7d,02845ded25aa2a9cf29830e2fa49941067728653543a1a62f55f13fe966471a9cb,121.199.11.177,12368,1572062883888;031000001a0000006818f2be83d3b3f769b851faccb507d88c61b5463392d9d7,d8a257aae5d9252d7777fa4810a0851d91be63e6ff841b6216e11c3f9485378c,0328f7304e186bd1624155e8c0d8ab54a2a8fba6a3d41762a47fbf1e9e10f72972,120.77.2.117,17533,1572062883888;031000001a00000054c370f0693a265e7735c2adeef37dbbee9d4e121159a0b9,eb80bcc964f9350b55f0faf3555121aba5cef7f0050039ce7a7ce61e72c5edaa,036326e57fab040b3319318f29f0a9038e1cf977d9fb906ffbb0559705808457be,122.112.234.133,27340,1572062883888;"));
#endif
    config.Set("vpn", "SG", std::string(""));
    config.Set("vpn", "BR", std::string(""));
    config.Set("vpn", "CA", std::string(""));
    config.Set("vpn", "DE", std::string(""));
    config.Set("vpn", "FR", std::string(""));
    config.Set("vpn", "HK", std::string(""));
    config.Set("vpn", "ID", std::string(""));
    config.Set("vpn", "JP", std::string("")); 
    config.Set("vpn", "KR", std::string(""));
    config.Set("vpn", "NL", std::string(""));
    config.Set("vpn", "NZ", std::string(""));
    config.Set("vpn", "PT", std::string(""));
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

int VpnClient::EncryptData(char* seckey, int seclen, char* data, int data_len, char* out) {
    if (security::Aes::Encrypt(
            data,
            data_len,
            seckey,
            seclen,
            out) != security::kSecuritySuccess) {
        return -1;
    }

    return 0;
}

int VpnClient::DecryptData(char* seckey, int seclen, char* data, int data_len, char* out) {
    if (security::Aes::Decrypt(
            data,
            data_len,
            seckey,
            seclen,
            out) != security::kSecuritySuccess) {
        return -1;
    }

    return 0;
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

        auto tmp_ptr = iter->second;
        tx_map_.erase(iter);
        CLIENT_ERROR("get transaction info success[%s]", tx_gid.c_str());
        return "";
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
                (*qiter)->svr_port = common::GetVpnServerPort(
                        common::Encode::HexDecode((*qiter)->dht_key),
                        common::TimeUtils::TimestampDays());
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
                (*qiter)->route_port = common::GetVpnRoutePort(
                        common::Encode::HexDecode((*qiter)->dht_key),
                        common::TimeUtils::TimestampDays());
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
    vpn_nodes_tick_->CutOff(kGetVpnNodesPeriod, std::bind(&VpnClient::GetVpnNodes, this));
}

void VpnClient::GetNetworkNodes(
        const std::vector<std::string>& country_vec,
        uint32_t network_id) {
    auto now_tick = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < country_vec.size(); ++i) {
        auto country = country_vec[i];
        auto uni_dht = std::dynamic_pointer_cast<network::Universal>(
            network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId));
        if (!uni_dht) {
            continue;
        }

        auto dht_nodes = uni_dht->LocalGetNetworkNodes(
                (uint32_t)network_id,
                (uint8_t)common::global_country_map[country],
                (uint32_t)4);
        if (dht_nodes.empty()) {
            continue;
        }

        for (auto iter = dht_nodes.begin(); iter != dht_nodes.end(); ++iter) {
            auto& tmp_node = *iter;
            uint16_t vpn_svr_port = 0;
            uint16_t vpn_route_port = 0;
            uint32_t node_netid = dht::DhtKeyManager::DhtKeyGetNetId(tmp_node->dht_key);
            if (node_netid == network::kVpnNetworkId) {
                vpn_svr_port = common::GetVpnServerPort(
                        tmp_node->dht_key,
                        common::TimeUtils::TimestampDays());
            } else if (node_netid == network::kVpnRouteNetworkId) {
                vpn_route_port = common::GetVpnRoutePort(
                        tmp_node->dht_key,
                        common::TimeUtils::TimestampDays());
            }

            // ecdh encrypt vpn password
            std::string sec_key;
            auto res = security::EcdhCreateKey::Instance()->CreateKey(
                    *(tmp_node->pubkey_ptr),
                    sec_key);
            if (res != security::kSecuritySuccess) {
                CLIENT_ERROR("create sec key failed!");
                continue;;
            }

            auto node_ptr = std::make_shared<VpnServerNode>(
                    tmp_node->public_ip,
                    vpn_svr_port,
                    vpn_route_port,
                    common::Encode::HexEncode(sec_key),
                    common::Encode::HexEncode(tmp_node->dht_key),
                    common::Encode::HexEncode(tmp_node->pubkey_str),
                    common::Encode::HexEncode(network::GetAccountAddressByPublicKey(tmp_node->pubkey_str)),
                    true);
            if (node_netid == network::kVpnNetworkId) {
                CLIENT_ERROR("get vpn node: %s:%d", node_ptr->ip.c_str(), node_ptr->svr_port);
                std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
                auto sub_iter = vpn_nodes_map_.find(country);
                if (sub_iter != vpn_nodes_map_.end()) {
                    auto e_iter = std::find_if(
                        sub_iter->second.begin(),
                        sub_iter->second.end(),
                            [node_ptr](const VpnServerNodePtr& ptr) {
                                return node_ptr->ip == ptr->ip && node_ptr->svr_port == ptr->svr_port;
                            });
                    if (e_iter == sub_iter->second.end()) {
                        sub_iter->second.push_back(node_ptr);
                        if (sub_iter->second.size() > 16) {
                            sub_iter->second.pop_front();
                        }
                    }
                }
            }

            if (node_netid == network::kVpnRouteNetworkId) {
                std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
                auto sub_iter = route_nodes_map_.find(country);
                if (sub_iter != route_nodes_map_.end()) {
                    auto e_iter = std::find_if(
                        sub_iter->second.begin(),
                        sub_iter->second.end(),
                        [node_ptr](const VpnServerNodePtr& ptr) {
                        return node_ptr->dht_key == ptr->dht_key;
                    });
                    if (e_iter == sub_iter->second.end()) {
                        sub_iter->second.push_back(node_ptr);
                        if (sub_iter->second.size() > 16) {
                            sub_iter->second.pop_front();
                        }
                    }
                }
            }
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

    uint32_t type = common::kConsensusTransaction;
    if (to.empty()) {
        type = common::kConsensusCreateAcount;
    }

    ClientProto::CreateTxRequest(
            uni_dht->local_node(),
            tx_gid,
            to_addr,
            amount,
            rand_num,
            type,
            msg);
    network::Route::Instance()->Send(msg);
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
	GetVpnVersion();
    check_tx_tick_->CutOff(kCheckTxPeriod, std::bind(&VpnClient::CheckTxExists, this));
}

int VpnClient::VpnLogin(
        const std::string& svr_account,
        const std::vector<std::string>& route_vec,
        std::string& login_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
			network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return kClientError;
    }
    login_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    uint32_t type = common::kConsensusTransaction;
    ClientProto::CreateVpnLoginRequest(
            uni_dht->local_node(),
            login_gid,
            common::Encode::HexDecode(svr_account),
            route_vec,
            msg);
    network::Route::Instance()->Send(msg);
    login_gid = common::Encode::HexEncode(login_gid);
    CLIENT_ERROR("sent vpn login request: %s", svr_account.c_str());
    return kClientSuccess;
}

int VpnClient::VpnLogout() {
    return kClientSuccess;
}

protobuf::BlockPtr VpnClient::GetBlockWithGid(const std::string& tx_gid) {
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

protobuf::BlockPtr VpnClient::GetBlockWithHash(const std::string& block_hash) {
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
    std::string account_address = network::GetAccountAddressByPublicKey(
        security::Schnorr::Instance()->str_pubkey());

    ClientProto::GetAccountHeight(uni_dht->local_node(), msg, account_address);
    uni_dht->SendToClosestNode(msg);
}

void VpnClient::GetVpnVersion() {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }
    transport::protobuf::Header msg;
    uni_dht->SetFrequently(msg);
    ClientProto::GetAccountHeight(uni_dht->local_node(), msg, kCheckVersionAccount);
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
        height_set = local_account_height_set_;
    }

    uint32_t sended_req = 0;
	std::string account_address = network::GetAccountAddressByPublicKey(
		security::Schnorr::Instance()->str_pubkey());
    for (auto iter = height_set.rbegin(); iter != height_set.rend(); ++iter) {
        auto height = *iter;
        {
            auto tmp_iter = hight_block_map_.find(height);
            if (tmp_iter != hight_block_map_.end()) {
                continue;
            }
        }
        transport::protobuf::Header msg;
        uni_dht->SetFrequently(msg);
        ClientProto::GetBlockWithHeight(uni_dht->local_node(), account_address, height, msg);
        uni_dht->SendToClosestNode(msg);
        ++sended_req;
        if (sended_req > 30) {
            break;
        }
    }
}

void VpnClient::DumpNodeToConfig() {
    DumpVpnNodes();
    DumpRouteNodes();
    config.DumpConfig(config_path_);
    dump_config_tick_->CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpNodeToConfig, this));
}

void VpnClient::DumpVpnNodes() {
    std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
    std::string country_list;
    auto tp = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
    for (auto iter = vpn_nodes_map_.begin(); iter != vpn_nodes_map_.end(); ++iter) {
#ifdef IOS_PLATFORM
		if (iter->first == "CN") {
			continue;
		}
#endif
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->svr_port) + "," +
                    std::to_string(timestamp));
            conf_str += tmp_str + ";";
        }
        config.Set("vpn", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("vpn", "country", country_list);
}

void VpnClient::DumpRouteNodes() {
    std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
    std::string country_list;
    for (auto iter = route_nodes_map_.begin(); iter != route_nodes_map_.end(); ++iter) {
#ifdef IOS_PLATFORM
		if (iter->first == "CN") {
			continue;
		}
#endif
        std::string conf_str;
        for (auto qiter = iter->second.rbegin(); qiter != iter->second.rend(); ++qiter) {
            std::string tmp_str;
            tmp_str = ((*qiter)->dht_key + "," +
                    (*qiter)->seckey + "," +
                    (*qiter)->pubkey + "," +
                    (*qiter)->ip + "," +
                    std::to_string((*qiter)->route_port));
            conf_str += tmp_str + ";";
        }
        config.Set("route", iter->first, conf_str);
        country_list += iter->first + ",";
    }
    config.Set("route", "country", country_list);
}

void VpnClient::ReadRouteNodesFromConf() {
    std::string country_list;
    config.Get("route", "country", country_list);
    if (country_list.empty()) {
        return;
    }

    common::Split country_split(country_list.c_str(), ',', country_list.size());
    for (uint32_t i = 0; i < country_split.Count(); ++i) {
        if (country_split.SubLen(i) <= 1) {
            continue;
        }

        std::string route_nodes;
        config.Get("route", country_split[i], route_nodes);
        if (route_nodes.empty()) {
            continue;
        }

        common::Split node_list(route_nodes.c_str(), ';', route_nodes.size());
        for (uint32_t node_idx = 0; node_idx < node_list.Count(); ++node_idx) {
            if (node_list.SubLen(node_idx) <= 10) {
                continue;
            }

            common::Split item_split(node_list[node_idx], ',', node_list.SubLen(node_idx));
            if (item_split.Count() < 5) {
                continue;
            }

            auto dht_key = common::Encode::HexDecode(item_split[0]);
            auto dht_netid = dht::DhtKeyManager::DhtKeyGetNetId(dht_key);
            if (dht_netid != network::kVpnRouteNetworkId) {
                continue;
            }

            std::string seckey;
            security::PublicKey pubkey(common::Encode::HexDecode(item_split[2]));
            int res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, seckey);
            if (res != security::kSecuritySuccess) {
                continue;
            }

            auto node_item = std::make_shared<VpnServerNode>(
                    item_split[3],
                    0,
                    0,
                    common::Encode::HexEncode(seckey),
                    item_split[0],
                    item_split[2],
                    common::Encode::HexEncode(network::GetAccountAddressByPublicKey(
                            common::Encode::HexDecode(item_split[2]))),
                    false);
            std::lock_guard<std::mutex> guard(route_nodes_map_mutex_);
            auto iter = route_nodes_map_.find(country_split[i]);
            if (iter == route_nodes_map_.end()) {
                route_nodes_map_[country_split[i]] = std::deque<VpnServerNodePtr>();
                route_nodes_map_[country_split[i]].push_back(node_item);
                continue;
            }

            auto e_iter = std::find_if(
                    iter->second.begin(),
                    iter->second.end(),
                    [node_item](const VpnServerNodePtr& ptr) {
                return node_item->dht_key == ptr->dht_key;
            });

            if (e_iter == iter->second.end()) {
                iter->second.push_back(node_item);
                if (iter->second.size() > 16) {
                    iter->second.pop_front();
                }
            }
        }
    }
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

            auto dht_key = common::Encode::HexDecode(item_split[0]);
            auto dht_netid = dht::DhtKeyManager::DhtKeyGetNetId(dht_key);
            if (dht_netid != network::kVpnNetworkId) {
                continue;
            }

            std::string seckey;
            security::PublicKey pubkey(common::Encode::HexDecode(item_split[2]));
            int res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, seckey);
            if (res != security::kSecuritySuccess) {
                continue;
            }

            auto node_item = std::make_shared<VpnServerNode>(
                    item_split[3],
                    0,
                    0,
                    common::Encode::HexEncode(seckey),
                    item_split[0],
                    item_split[2],
                    common::Encode::HexEncode(network::GetAccountAddressByPublicKey(
                            common::Encode::HexDecode(item_split[2]))),
                    false);
            std::lock_guard<std::mutex> guard(vpn_nodes_map_mutex_);
            auto iter = vpn_nodes_map_.find(country_split[i]);
            if (iter == vpn_nodes_map_.end()) {
                vpn_nodes_map_[country_split[i]] = std::deque<VpnServerNodePtr>();
                vpn_nodes_map_[country_split[i]].push_back(node_item);
                continue;
            }

            auto e_iter = std::find_if(
                    iter->second.begin(),
                    iter->second.end(),
                    [node_item](const VpnServerNodePtr& ptr) {
                return node_item->dht_key == ptr->dht_key;
            });
            if (e_iter == iter->second.end()) {
                iter->second.push_back(node_item);
                if (iter->second.size() > 16) {
                    iter->second.pop_front();
                }
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

    dump_bootstrap_tick_->CutOff(
            60ull * 1000ull * 1000ull,
            std::bind(&VpnClient::DumpBootstrapNodes, this));
}

std::string VpnClient::GetRouting(const std::string& start, const std::string& end) {
    return "";
}

}  // namespace client

}  // namespace lego
