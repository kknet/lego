#include "stdafx.h"
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
#include "contract/proto/contract_proto.h"
#include "contract/contract_utils.h"
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

VpnClient::VpnClientc   () {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));
    network::Route::Instance()->RegisterMessage(
            common::kContractMessage,
            std::bind(&VpnClient::HandleMessage, this, std::placeholders::_1));

	vpn_download_url_ = kClientDownloadUrl;
	check_tx_tick_ = std::make_shared<common::Tick>();
	vpn_nodes_tick_ = std::make_shared<common::Tick>();
	dump_config_tick_ = std::make_shared<common::Tick>();
	dump_bootstrap_tick_ = std::make_shared<common::Tick>();
    paied_vip_info_[0] = std::make_shared<LastPaiedVipInfo>();
    paied_vip_info_[0]->height = 0;
    paied_vip_info_[0]->timestamp = 0;
    paied_vip_info_[1] = nullptr;
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

    if (header.type() == common::kContractMessage) {
        HandleContractMessage(header);
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

    if (block_msg.has_acc_attr_res()) {
        HandleCheckVipResponse(header, block_msg);
    }
}

void VpnClient::HandleContractMessage(transport::protobuf::Header& header) {
    contract::protobuf::ContractMessage contract_msg;
    if (!contract_msg.ParseFromString(header.data())) {
        return;
    }

    if (contract_msg.has_get_attr_res()) {
        auto client_bw_res = contract_msg.get_attr_res();
        std::string key = client_bw_res.attr_key();
        common::Split key_split(key.c_str(), '_', key.size());
        if (key_split.Count() != 3) {
            return;
        }

        auto today_timestamp = std::to_string(common::TimeUtils::TimestampDays());
        if (today_timestamp != key_split[2]) {
            return;
        }

        try {
            today_used_bandwidth_ = common::StringUtil::ToUint32(client_bw_res.attr_value());
        } catch (...) {
        }
    }
}

void VpnClient::HandleCheckVipResponse(
        transport::protobuf::Header& header,
        client::protobuf::BlockMessage& block_msg) {
    auto& attr_res = block_msg.acc_attr_res();
    CLIENT_ERROR("receive get attr[%s] block[%d] height[%llu] info.", attr_res.attr_key().c_str(), attr_res.block().empty(), paied_vip_info_[paied_vip_valid_idx_]->height);
    if (attr_res.block().empty()) {
        if (paied_vip_info_[paied_vip_valid_idx_]->timestamp == 0) {
            paied_vip_info_[paied_vip_valid_idx_]->timestamp = kInvalidTimestamp;
        }

        return;
    }

    client::protobuf::Block block;
    if (!block.ParseFromString(attr_res.block())) {
        return;
    }

    // TODO(): check block multi sign, this node must get election blocks
    std::string login_svr_id;
    auto& tx_list = block.tx_block().tx_list();
    for (int32_t i = tx_list.size() - 1; i >= 0; --i) {
        if (tx_list[i].attr_size() > 0) {
            if (tx_list[i].from() != attr_res.account()) {
                continue;
            }

            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                if (tx_list[i].attr(attr_idx).key() == common::kUserPayForVpn) {
                    auto paied_vip_ptr = std::make_shared<LastPaiedVipInfo>();
                    paied_vip_ptr->amount = tx_list[i].amount();
                    paied_vip_ptr->block_hash = block.hash();
                    paied_vip_ptr->height = block.height();
                    paied_vip_ptr->timestamp = block.timestamp();
                    paied_vip_ptr->to_account = tx_list[i].to();
                    if (paied_vip_valid_idx_ == 0) {
                        paied_vip_info_[1] = paied_vip_ptr;
                        paied_vip_valid_idx_ = 1;
                    } else {
                        paied_vip_info_[0] = paied_vip_ptr;
                        paied_vip_valid_idx_ = 0;
                    }
                    break;
                }
            }
        }
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

void VpnClient::SendGetAccountAttrUsedBandwidth() {
    auto uni_dht = lego::network::DhtManager::Instance()->GetDht(
            lego::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string key = (common::kIncreaseVpnBandwidth + "_" +
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()) + "_" +
            now_day_timestamp);
    contract::ContractProto::CreateGetAttrRequest(
            uni_dht->local_node(),
            common::GlobalInfo::Instance()->id(),
            contract::kContractVpnBandwidthProveAddr,
            key,
            msg);
    network::Route::Instance()->Send(msg);
}

std::string VpnClient::CheckFreeBandwidth() {
    SendGetAccountAttrUsedBandwidth();
    return std::to_string(today_used_bandwidth_);
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

    std::string def_conf;
    config.Get("route", "def_routing", def_conf);
    if (def_conf.empty()) {
        SetDefaultRouting();
        config.Get("route", "def_routing", def_conf);
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
            common::Encode::HexEncode(security::Schnorr::Instance()->str_prikey()) +
            "," + def_conf);
}

void VpnClient::InitRouteAndVpnServer() {    
	config.Set("route", "country", std::string("AU,BR,CA,CN,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
    config.Set("route", "US", std::string("04100000380000009a544ea0f2bfbf6430d7092cc446750da9f9107a26744095,e7673b77000b903197622216e234df90979a518ce5fc3cbc2ac1f13bca4711a9,0294e541207cef73721365ab004a8d03a441bbc5645742799c0d1cdbc47275f7b5,67.198.205.109,47644;041000003800000099396a8250dd53d48fc2a5b21d0b17dcd8e3e467cf5196a7,39935681a82494d2663690470ec4d12aba9118be165eb95c3d93c9569100a626,02fcdbe9f69c15ca4e0bd3c8d42db6dc3757f1bf41c0e7531234f4de36360e44e0,198.11.180.173,58757;04100000380000008e51d398627f2ab3eb4f5a26ce70a3664877f5e6a6ab71b1,03136ec9a430d22e54ac49035634a42d9330b6b40221152f072f40da6808024a,02661104d61edf0cea2542b9236918c4b7f287308aad036303cdd2133d0aa4d6e9,104.238.182.175,41629;0410000038000000b558246e977dd94683a6f60de97a26fc9eba939d2f4d5f6c,ee3a0076bdb12b9cacaca18eab7a1fc43c2c48706908b5782cb2e59f910c6899,03d58dcc073a2e5b16b535b12c583f68a7b4df037e769d57e4e54ffd9b79518a02,142.93.53.134,45255;0410000038000000a9b7e333749bfcfa22cc760ca46d4afa46608ff8b3679835,b06997ebb5c2039c95de337b93ced71e516c55fb39a405f3c4490e3fbefa1cca,0321d47913356026a7fb608f0256ffe435bc089a52995b72871705f7fb4316b598,178.128.146.118,62045;041000003800000028eec67053b3db77971001c7300a85094032092ed03605f3,de32408a4eff8fa0e28c5453bd211ea46a80cb7fd6e9cc64095574c5cdc6155c,02a1185d6084dd5d895191bd70da184500fe170975dae1270baf68079a8352cc95,98.126.31.159,38668;041000003800000057e24e525f44f8441d7582207a921d2b7162905b9abe4bfa,11fc3f2d2a9d3d2fe52fa670012df3344d704ccf0e69b9ba8f37d218d5eef7d7,032ea9f614d99db11ad4216f2eec4fa32db7580e89e4dd9deda587bef77807220e,47.252.20.241,50467;"));
    config.Set("route", "SG", std::string("041000008600000009b33c1a61a26e71293eefad1e76f17c0574830a5eeb27b4,75644d7c6c7e704ba4199e7e1cfd6d1ffa687d96b005eafe698c161a052f1f2d,0304c6d02c26cd35bedfd81b9d37093806a882ba8d91db5893c63834d4406a9e45,165.22.105.132,59711;04100000860000007ebc8a9ced7fc13c24950ac0ac1cb0ffa79c3ad6a5a0cc05,a08598b12b521f81529203ddd826954c233bf9337223d69c7432829a73a6d697,020040e5d618fb909d9ad8f470cca41c0feba458bd7a48dcfae9c6ebc2a24c0d54,159.89.206.184,57660;0410000086000000a0b5ec5bf6dce8b25b19e2e0955f177f2201a3f33c8a0e7b,ab18038c07f3eb6baa88057cb1fbd13700e0596c882b38bb7cdab0ee5820789c,0305589974caff7bb423fa49f632fa8422a13eef2908a10161c1b7d1528ccbdd2e,159.89.206.115,41827;0410000086000000c848831d59bc84a194b0af0b798681960389f381a66d01ac,93379db94ae064c66d3b13f266a53d3fc1f7ab334b99d4e73b57e48f145a8c71,02c568482bd9f25971c3fb741bf64c403238c41e761cda2e7a31ddd4cfc124b05e,165.22.105.214,61139;"));
    config.Set("route", "NL", std::string("04100000ec0000000fb3e05efc0f8eeafbc729a16bc173e4d3619a95b75f3d7b,f54106633d7ce6a180d2f8507b43ffe8e1e23d159492d1977d6df07e808aa7e6,033049ee5e5f70a58b73fb746e17af3ac17c2845000bba50f776863253274b9af9,165.22.207.251,51122;04100000ec000000cc9049af5600feb50c503999dfc93d306d50d19d3a8299fb,353a63e9672b906192e9e4f0522acfb34a89c160e6a76d2fa7c2e5c93cff9512,03a066eb9d66399c9044a114dea41be33c74884481c578285f3633c408a4d5e877,142.93.226.174,35046;04100000ec00000033d20229a86ac2508e239a838751f141d81a8519ebdcc077,ba8cbbf8470f4d16fb1832bc8dc0833e87c044e6d492d173f33c21fcb07e8af2,0261adfa5b035be2cd039d52dc561fd1f799f062fbdbe1a25d805f583842dd5d9d,142.93.142.156,53105;"));
    config.Set("route", "JP", std::string("041000001b000000b32059940c6baf6378f4feb5b5bfccdaf89ce5acff5b4b09,8a2b449b34f44649f9f028ecb20632a69fde371214432d2b550246f5b7fda319,0239567f33855404c81d131488dc2382b024e6e8fc75817f1f862fa21ab9ab28d0,45.76.53.23,42043;041000001b000000e68850a284c7e2825fdd0c58cb3b1fd630b67a87ae46a556,ec522d9d50ac30aff92ab0a5d088870f6640f0252d107ec5e13f93f6e95b04b1,02f38cfe6f38f9ee0fffe40af8ea3bf7690d17f766ff1936ea9a1b466b1dcb9313,198.13.47.173,35954;041000001b00000062fea13cfba6115d625088d47f83e596a51a91190911f30d,520a7562329388747fcb8421d186522629d93a52a1a3b9c0dae26558cebf5cd9,0261a75ac1fc683eebfc8283566dc35593a31aabd4db0fadaa4261d075b8b450f2,45.77.131.232,64983;"));
    config.Set("route", "IN", std::string("04100000740000009f1354ef6fc9624a72671b32d1ddacdafd28deb4a0d4777b,78c413c64b60056d8c173bc83ad98400a223fcde80712b4ded8cb5cc1cfe5e7b,033e70c258240dd45f8c7f2a8a027764863f7a50558bf88ba182161d8753abebe8,149.129.147.55,57860;"));
    config.Set("route", "GB", std::string("04100000ed00000002d2c69b310d0fd54b9a60d7b82110bf2cc9bcf7ab629b51,c780a84744e25aca0861441bd0d05b310cf786fafa503e8be04443a37bab086c,03454758672dd15f3f1a02d3c9ebc9eb6b473a78187657de62e9dce6673895ba65,142.93.35.17,62020;04100000ed000000e21fafeef8e24b8137707a5b3d8574655758a03ebba11c7b,a5ca535c77b57150f1c6fdd192bff627e4d91e601a90bf673effa0143bdd15ba,0291a4212e40b97e06082ff0689b2b01a1258b15305e70d43bfd731e20804051a8,8.208.14.63,47652;"));
    config.Set("route", "FR", std::string("04100000e7000000b158c727b60eee1b8892cdfb6504e5ec25207c72e59810a4,b276e3e8f611a1f572bfefe6682668833a44dbb6ab742c54d937d7338df52d39,02bb280ae1be2ed72811cec6771d1816d4661aec0a5323044489cb1a9308b917af,95.179.209.137,53769;04100000e700000048dfe5a91586e9a2c1ca42cb3abb60905a26bb34874cf420,6563d2ee103e937251ce96d4de4e470f29edadd48c030a82a7c5dde0d041da3a,02085cf5a31329ac222a51273c9ddd9814ab8adb07625eb38e7d08f0790df649b0,217.69.7.16,61846;04100000e70000004ce32204a5620171e5b96b73a84db4b597380d3ad0e1a75b,a4ad5cf1a137fb708bc06290a8aac27771413a2fc5d007988f3e22001ed4dc32,02f60f9d4ba1db2e32dc4cd2be740fee7c26f94a8953ef68e98547e5d5d2036bcd,95.179.210.33,40240;"));
    config.Set("route", "DE", std::string("04100000e8000000d8091519a95fe8a96e82a0cc6e76d6ddb94a54dd5f8ecc3f,af77800eaeeb1d577df182272f004cf6ce8cc4fb756000994e2c2364abcae923,02e13c4091801a1a8477796b2339c7a42492750504d4f486b2fe0d0aa8dae2da34,47.91.94.168,48745;04100000e8000000db4b6ae79c161eee8f43d370169db225e06e7b43592d5e7e,2fe7862db363d7fa5639b5c609b6ef2414e115fcadbb16830752d25378d701f5,03c2c39e48536c6e5ae137391cf811b48f6df4d2cd79ec9c68c42a7ace67ad81b9,167.71.48.57,49212;04100000e8000000645a51d933b90738a35f3a03b101daac2aa5ed82fd38811a,34a3785a11d58c23df8aaf852921ff0247f545950b3bdce8555e04e3f5bad92a,02184d55912cef53bd499543cc46b6aaa13c066191e4b4e6df170dc776a1ba1e2d,167.71.48.44,59006;"));
    config.Set("route", "CN", std::string("041000001a000000da64fc6ab8000a7dd8cd2abc987df2e7657c54d9fae7e8e9,fef1190435d8bd781bfec983c07b1f72dd2d6df4fde2fc3769550c36e127ab96,039ba9f79fe35b09de63aa80238770600e0d8829df778a4fe71c8128a61df0deb8,47.108.85.32,50747;041000001a00000005fe9d923c3742c249a9e6343b4a3bb2cae2b20fec6336da,dbbc4ee1733f0584da32e11f3855e42876d83c171d72f32be0fcf79dc75bdd8e,02845ded25aa2a9cf29830e2fa49941067728653543a1a62f55f13fe966471a9cb,121.199.11.177,44922;041000001a00000023b167ff2bc4fa5765c345b4addbe0ff8b1abe5d0af010eb,1e45d0dad4ed2f9090a59357479769ae099cf85d81df13e68a7fd978c6c60a11,035acb6ec65d1bd35224d3d64d4cd278fcbf80e4886522872b13b9de658b59e2cc,47.105.87.61,39899;041000001a0000006818f2be83d3b3f769b851faccb507d88c61b5463392d9d7,b8097e80caf6159e87982ed6bf47bbcb8467be3156159ab027ae1b6f59eac405,0328f7304e186bd1624155e8c0d8ab54a2a8fba6a3d41762a47fbf1e9e10f72972,120.77.2.117,37775;"));
    config.Set("route", "CA", std::string("0410000035000000eabc8c1fdfd76fd0f1a64926a384214e82f0be21e61ecec1,951dcf89f22079d474a52b0866d36965f78a702382a5daf7ec489f5ecc90cc7b,030499fff02cb8d97fab6b241a1dd99b76ead836bf6606d51bab5ebcfb5dd962ae,138.197.174.57,58805;0410000035000000e048012dc1ff1ea0a6458a5614b8133e6b39adb6b536d932,6bc20d904b19804695fc6d34004602bcae65d694e542d4e09ec6413506df6355,0348e04787912a878d0e5da49846ce933d6c932b4f573f716223faf45e10c2249b,138.197.162.219,52929;0410000035000000f708d24b98a4a5cb5309ce143f591a82259c455dc6fbc862,ed4017b941eecee8b4ea8f7e172742c0152b8989a8e003f7512dceb07500a65c,03cb980f2e5b5ba8e9d2f4c15fb2330ea84f59d256051f3b4ad8aae5969df4e995,138.197.174.37,46570;"));
    config.Set("route", "AU", std::string("041000004b0000002d20171a6a87a92244967b3ece8571642f37a09aa164ea21,ccb746d11a3b3de3fe02c338aa5cb02a83edc3a13a7c8f01f5fb3c031cf06cb0,03eb0c8b35915245368be7f532af5e26403a38227bf4158f38d9f268f08f8f47a3,139.180.164.156,45665;041000004b000000109bb06a1fb948b97f8214ddcdadaafe8283856200a4b493,4be72b75bd686f430d21be815a962aff08fa7d96388821a94f839a980ad977fe,02490ecb5963d22b94dec1f8561438603bcad9a94a1ab88249120ac4c6f14826f4,108.61.96.210,49690;041000004b0000006098700953ecbfeab0dad0501dc212e5e64684291304c394,720cdd6aba247b849c8b758111180d9454ed7170fab986844572b62c7f27de3a,034a767477ccf4dd0ba787af5ff5720b565fd5bec6cfca05c816d8ccb61c98cbf1,139.180.163.51,56248;"));
    config.Set("vpn", "country", std::string("AU,BR,CA,CN,DE,FR,GB,HK,ID,IN,JP,KR,NL,NZ,PT,SG,US"));
    config.Set("vpn", "US", std::string("031000003800000028eec67053b3db77971001c7300a85094032092ed03605f3,de32408a4eff8fa0e28c5453bd211ea46a80cb7fd6e9cc64095574c5cdc6155c,02a1185d6084dd5d895191bd70da184500fe170975dae1270baf68079a8352cc95,98.126.31.159,19359,1573272498084;0310000038000000b558246e977dd94683a6f60de97a26fc9eba939d2f4d5f6c,ee3a0076bdb12b9cacaca18eab7a1fc43c2c48706908b5782cb2e59f910c6899,03d58dcc073a2e5b16b535b12c583f68a7b4df037e769d57e4e54ffd9b79518a02,142.93.53.134,21928,1573272498084;0310000038000000a9b7e333749bfcfa22cc760ca46d4afa46608ff8b3679835,b06997ebb5c2039c95de337b93ced71e516c55fb39a405f3c4490e3fbefa1cca,0321d47913356026a7fb608f0256ffe435bc089a52995b72871705f7fb4316b598,178.128.146.118,19305,1573272498084;03100000380000009a544ea0f2bfbf6430d7092cc446750da9f9107a26744095,e7673b77000b903197622216e234df90979a518ce5fc3cbc2ac1f13bca4711a9,0294e541207cef73721365ab004a8d03a441bbc5645742799c0d1cdbc47275f7b5,67.198.205.109,13596,1573272498084;031000003800000099396a8250dd53d48fc2a5b21d0b17dcd8e3e467cf5196a7,39935681a82494d2663690470ec4d12aba9118be165eb95c3d93c9569100a626,02fcdbe9f69c15ca4e0bd3c8d42db6dc3757f1bf41c0e7531234f4de36360e44e0,198.11.180.173,13885,1573272498084;03100000380000008e51d398627f2ab3eb4f5a26ce70a3664877f5e6a6ab71b1,03136ec9a430d22e54ac49035634a42d9330b6b40221152f072f40da6808024a,02661104d61edf0cea2542b9236918c4b7f287308aad036303cdd2133d0aa4d6e9,104.238.182.175,11873,1573272498084;031000003800000057e24e525f44f8441d7582207a921d2b7162905b9abe4bfa,11fc3f2d2a9d3d2fe52fa670012df3344d704ccf0e69b9ba8f37d218d5eef7d7,032ea9f614d99db11ad4216f2eec4fa32db7580e89e4dd9deda587bef77807220e,47.252.20.241,30105,1573272498084;"));
    config.Set("vpn", "IN", std::string("03100000740000009f1354ef6fc9624a72671b32d1ddacdafd28deb4a0d4777b,78c413c64b60056d8c173bc83ad98400a223fcde80712b4ded8cb5cc1cfe5e7b,033e70c258240dd45f8c7f2a8a027764863f7a50558bf88ba182161d8753abebe8,149.129.147.55,20320,1573272498084;03100000740000000656aa99d71fce7cb351ff4942ffa409f81eea456bd9ed17,0c0e2bf18ee958a3bc2875dfcfa8578bb895b33b8df5c1d2815b606aff5ea813,020013493f20263cac6d31c5b12cb789475122add77eaaee0dfa0d57a30fe5c5c8,139.59.85.218,31164,1573272498084;"));
    config.Set("vpn", "GB", std::string("03100000ed000000e21fafeef8e24b8137707a5b3d8574655758a03ebba11c7b,a5ca535c77b57150f1c6fdd192bff627e4d91e601a90bf673effa0143bdd15ba,0291a4212e40b97e06082ff0689b2b01a1258b15305e70d43bfd731e20804051a8,8.208.14.63,12888,1573272498084;03100000ed00000002d2c69b310d0fd54b9a60d7b82110bf2cc9bcf7ab629b51,c780a84744e25aca0861441bd0d05b310cf786fafa503e8be04443a37bab086c,03454758672dd15f3f1a02d3c9ebc9eb6b473a78187657de62e9dce6673895ba65,142.93.35.17,33889,1573272498084;"));
    config.Set("vpn", "CN", std::string("031000001a000000da64fc6ab8000a7dd8cd2abc987df2e7657c54d9fae7e8e9,fef1190435d8bd781bfec983c07b1f72dd2d6df4fde2fc3769550c36e127ab96,039ba9f79fe35b09de63aa80238770600e0d8829df778a4fe71c8128a61df0deb8,47.108.85.32,24514,1573272498084;031000001a00000054c370f0693a265e7735c2adeef37dbbee9d4e121159a0b9,97ef8637f1d530a35539b2dbdac00c6af4cbcd3feadb0b75bcf81e00f3abf517,036326e57fab040b3319318f29f0a9038e1cf977d9fb906ffbb0559705808457be,122.112.234.133,13842,1573272498084;031000001a0000006818f2be83d3b3f769b851faccb507d88c61b5463392d9d7,b8097e80caf6159e87982ed6bf47bbcb8467be3156159ab027ae1b6f59eac405,0328f7304e186bd1624155e8c0d8ab54a2a8fba6a3d41762a47fbf1e9e10f72972,120.77.2.117,21007,1573272498084;031000001a00000005fe9d923c3742c249a9e6343b4a3bb2cae2b20fec6336da,dbbc4ee1733f0584da32e11f3855e42876d83c171d72f32be0fcf79dc75bdd8e,02845ded25aa2a9cf29830e2fa49941067728653543a1a62f55f13fe966471a9cb,121.199.11.177,21773,1573272498084;031000001a00000023b167ff2bc4fa5765c345b4addbe0ff8b1abe5d0af010eb,1e45d0dad4ed2f9090a59357479769ae099cf85d81df13e68a7fd978c6c60a11,035acb6ec65d1bd35224d3d64d4cd278fcbf80e4886522872b13b9de658b59e2cc,47.105.87.61,34139,1573272498084;"));
    config.Set("vpn", "SG", std::string("0310000086000000a0b5ec5bf6dce8b25b19e2e0955f177f2201a3f33c8a0e7b,ab18038c07f3eb6baa88057cb1fbd13700e0596c882b38bb7cdab0ee5820789c,0305589974caff7bb423fa49f632fa8422a13eef2908a10161c1b7d1528ccbdd2e,159.89.206.115,16855,1573272498084;03100000860000007ebc8a9ced7fc13c24950ac0ac1cb0ffa79c3ad6a5a0cc05,a08598b12b521f81529203ddd826954c233bf9337223d69c7432829a73a6d697,020040e5d618fb909d9ad8f470cca41c0feba458bd7a48dcfae9c6ebc2a24c0d54,159.89.206.184,20079,1573272498084;0310000086000000beea322a62cf3685dc9424210506ace6cb330629e8fec5d0,eeb4657f344161c1ca50fbdc8e98f03b63dc5a8b150df58501cf2eac2aceaaa3,02db5169ceb32fa90899c9aa2e5eed0f06aa262fa2f6a6b3603d04742cd84835d2,47.88.223.66,28984,1573272498084;0310000086000000c848831d59bc84a194b0af0b798681960389f381a66d01ac,93379db94ae064c66d3b13f266a53d3fc1f7ab334b99d4e73b57e48f145a8c71,02c568482bd9f25971c3fb741bf64c403238c41e761cda2e7a31ddd4cfc124b05e,165.22.105.214,13170,1573272498084;031000008600000009b33c1a61a26e71293eefad1e76f17c0574830a5eeb27b4,75644d7c6c7e704ba4199e7e1cfd6d1ffa687d96b005eafe698c161a052f1f2d,0304c6d02c26cd35bedfd81b9d37093806a882ba8d91db5893c63834d4406a9e45,165.22.105.132,14606,1573272498084;"));
    config.Set("vpn", "BR", std::string(""));
    config.Set("vpn", "CA", std::string("0310000035000000f708d24b98a4a5cb5309ce143f591a82259c455dc6fbc862,ed4017b941eecee8b4ea8f7e172742c0152b8989a8e003f7512dceb07500a65c,03cb980f2e5b5ba8e9d2f4c15fb2330ea84f59d256051f3b4ad8aae5969df4e995,138.197.174.37,10277,1573272498084;0310000035000000eabc8c1fdfd76fd0f1a64926a384214e82f0be21e61ecec1,951dcf89f22079d474a52b0866d36965f78a702382a5daf7ec489f5ecc90cc7b,030499fff02cb8d97fab6b241a1dd99b76ead836bf6606d51bab5ebcfb5dd962ae,138.197.174.57,13416,1573272498084;0310000035000000e048012dc1ff1ea0a6458a5614b8133e6b39adb6b536d932,6bc20d904b19804695fc6d34004602bcae65d694e542d4e09ec6413506df6355,0348e04787912a878d0e5da49846ce933d6c932b4f573f716223faf45e10c2249b,138.197.162.219,15610,1573272498084;"));
    config.Set("vpn", "DE", std::string("03100000e8000000645a51d933b90738a35f3a03b101daac2aa5ed82fd38811a,34a3785a11d58c23df8aaf852921ff0247f545950b3bdce8555e04e3f5bad92a,02184d55912cef53bd499543cc46b6aaa13c066191e4b4e6df170dc776a1ba1e2d,167.71.48.44,20569,1573272498084;03100000e8000000d8091519a95fe8a96e82a0cc6e76d6ddb94a54dd5f8ecc3f,af77800eaeeb1d577df182272f004cf6ce8cc4fb756000994e2c2364abcae923,02e13c4091801a1a8477796b2339c7a42492750504d4f486b2fe0d0aa8dae2da34,47.91.94.168,30170,1573272498084;03100000e8000000db4b6ae79c161eee8f43d370169db225e06e7b43592d5e7e,2fe7862db363d7fa5639b5c609b6ef2414e115fcadbb16830752d25378d701f5,03c2c39e48536c6e5ae137391cf811b48f6df4d2cd79ec9c68c42a7ace67ad81b9,167.71.48.57,32264,1573272498084;"));
    config.Set("vpn", "FR", std::string("03100000e7000000b158c727b60eee1b8892cdfb6504e5ec25207c72e59810a4,b276e3e8f611a1f572bfefe6682668833a44dbb6ab742c54d937d7338df52d39,02bb280ae1be2ed72811cec6771d1816d4661aec0a5323044489cb1a9308b917af,95.179.209.137,18214,1573272498084;03100000e70000004ce32204a5620171e5b96b73a84db4b597380d3ad0e1a75b,a4ad5cf1a137fb708bc06290a8aac27771413a2fc5d007988f3e22001ed4dc32,02f60f9d4ba1db2e32dc4cd2be740fee7c26f94a8953ef68e98547e5d5d2036bcd,95.179.210.33,19882,1573272498084;03100000e700000048dfe5a91586e9a2c1ca42cb3abb60905a26bb34874cf420,6563d2ee103e937251ce96d4de4e470f29edadd48c030a82a7c5dde0d041da3a,02085cf5a31329ac222a51273c9ddd9814ab8adb07625eb38e7d08f0790df649b0,217.69.7.16,31161,1573272498084;"));
    config.Set("vpn", "HK", std::string(""));
    config.Set("vpn", "ID", std::string(""));
    config.Set("vpn", "JP", std::string("031000001b000000e68850a284c7e2825fdd0c58cb3b1fd630b67a87ae46a556,ec522d9d50ac30aff92ab0a5d088870f6640f0252d107ec5e13f93f6e95b04b1,02f38cfe6f38f9ee0fffe40af8ea3bf7690d17f766ff1936ea9a1b466b1dcb9313,198.13.47.173,34661,1573272498084;031000001b00000062fea13cfba6115d625088d47f83e596a51a91190911f30d,520a7562329388747fcb8421d186522629d93a52a1a3b9c0dae26558cebf5cd9,0261a75ac1fc683eebfc8283566dc35593a31aabd4db0fadaa4261d075b8b450f2,45.77.131.232,14581,1573272498084;031000001b000000b32059940c6baf6378f4feb5b5bfccdaf89ce5acff5b4b09,8a2b449b34f44649f9f028ecb20632a69fde371214432d2b550246f5b7fda319,0239567f33855404c81d131488dc2382b024e6e8fc75817f1f862fa21ab9ab28d0,45.76.53.23,29485,1573272498084;")); 
    config.Set("vpn", "KR", std::string(""));
    config.Set("vpn", "NL", std::string("03100000ec000000cc9049af5600feb50c503999dfc93d306d50d19d3a8299fb,353a63e9672b906192e9e4f0522acfb34a89c160e6a76d2fa7c2e5c93cff9512,03a066eb9d66399c9044a114dea41be33c74884481c578285f3633c408a4d5e877,142.93.226.174,27078,1573272498084;03100000ec0000000fb3e05efc0f8eeafbc729a16bc173e4d3619a95b75f3d7b,f54106633d7ce6a180d2f8507b43ffe8e1e23d159492d1977d6df07e808aa7e6,033049ee5e5f70a58b73fb746e17af3ac17c2845000bba50f776863253274b9af9,165.22.207.251,22012,1573272498084;03100000ec00000033d20229a86ac2508e239a838751f141d81a8519ebdcc077,ba8cbbf8470f4d16fb1832bc8dc0833e87c044e6d492d173f33c21fcb07e8af2,0261adfa5b035be2cd039d52dc561fd1f799f062fbdbe1a25d805f583842dd5d9d,142.93.142.156,23503,1573272498084;"));
    config.Set("vpn", "NZ", std::string(""));
    config.Set("vpn", "PT", std::string(""));
    config.Set("vpn", "AU", std::string("031000004b0000002d20171a6a87a92244967b3ece8571642f37a09aa164ea21,ccb746d11a3b3de3fe02c338aa5cb02a83edc3a13a7c8f01f5fb3c031cf06cb0,03eb0c8b35915245368be7f532af5e26403a38227bf4158f38d9f268f08f8f47a3,139.180.164.156,32751,1573272498084;031000004b0000006098700953ecbfeab0dad0501dc212e5e64684291304c394,720cdd6aba247b849c8b758111180d9454ed7170fab986844572b62c7f27de3a,034a767477ccf4dd0ba787af5ff5720b565fd5bec6cfca05c816d8ccb61c98cbf1,139.180.163.51,20981,1573272498084;031000004b000000109bb06a1fb948b97f8214ddcdadaafe8283856200a4b493,4be72b75bd686f430d21be815a962aff08fa7d96388821a94f839a980ad977fe,02490ecb5963d22b94dec1f8561438603bcad9a94a1ab88249120ac4c6f14826f4,108.61.96.210,26428,1573272498084;"));
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
            dht_nodes = uni_dht->RemoteGetNetworkNodes(
                    (uint32_t)network_id,
                    (uint8_t)common::global_country_map[country],
                    (uint32_t)4);
            if (dht_nodes.empty()) {
                continue;
            }
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

std::string VpnClient::CheckVip() {
    SendGetAccountAttrLastBlock(
            common::kUserPayForVpn,
            common::GlobalInfo::Instance()->id(),
            paied_vip_info_[paied_vip_valid_idx_]->height);
    return std::to_string(paied_vip_info_[paied_vip_valid_idx_]->timestamp);
}

std::string VpnClient::PayForVPN(const std::string& to, const std::string& gid, uint64_t amount) {
    if (to.empty() || amount <= 0) {
        return "ERROR";
    }

    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return "ERROR";
    }
    auto tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    if (gid.size() == 32 * 2) {
        tx_gid = common::Encode::HexDecode(gid);
    }

    std::string to_addr = common::Encode::HexDecode(to);
    std::map<std::string, std::string> attrs = {
        { common::kUserPayForVpn, "" }
    };

    uint32_t type = common::kConsensusPayForCommonVpn;
    ClientProto::CreateTransactionWithAttr(
            uni_dht->local_node(),
            tx_gid,
            to_addr,
            amount,
            type,
            "",
            attrs,
            msg);
    network::Route::Instance()->Send(msg);
    return common::Encode::HexEncode(tx_gid);
}

void VpnClient::SendGetAccountAttrLastBlock(
        const std::string& attr,
        const std::string& account,
        uint64_t height) {
    uint64_t rand_num = 0;
    auto uni_dht = lego::network::DhtManager::Instance()->GetDht(
        lego::network::kVpnNetworkId);
    if (uni_dht == nullptr) {
        CLIENT_ERROR("not found vpn server dht.");
        return;
    }

    transport::protobuf::Header msg;
    client::ClientProto::AccountAttrRequest(
            uni_dht->local_node(),
            account,
            attr,
            height,
            msg);
    network::Route::Instance()->Send(msg);
    CLIENT_ERROR("send out get attr[%s] info.", attr.c_str());
}

std::string VpnClient::Transaction(const std::string& to, uint64_t amount, std::string& tx_gid) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return "ERROR";
    }

    if (tx_gid.size() == 32 * 2) {
        tx_gid = common::Encode::HexDecode(tx_gid);
    } else {
        tx_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
    }

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
    tx_gid = common::Encode::HexEncode(tx_gid);
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
        SendGetBlockWithGid(tmp_gid, true);
    }
    return nullptr;
}

protobuf::BlockPtr VpnClient::GetBlockWithHash(const std::string& block_hash) {
    auto dec_hash = common::Encode::HexDecode(block_hash);
    auto tmp_gid = std::string("b_") + dec_hash;
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
        SendGetBlockWithGid(dec_hash, false);
    }
    return nullptr;
}

void VpnClient::SendGetBlockWithGid(const std::string& str, bool is_gid) {
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }
    transport::protobuf::Header msg;
    ClientProto::GetBlockWithTxGid(uni_dht->local_node(), str, is_gid, true, msg);
    uni_dht->SendToClosestNode(msg);
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
    auto tp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count();
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

int VpnClient::SetDefaultRouting() {
    std::string def_conf = "PH:CN;PK:CN;VN:CN;BD:CN;ID:CN;MY:SG;CN:CN";
    if (!config.Set("route", "def_routing", def_conf)) {
        CLIENT_ERROR("set default config for [%s] failed", def_conf.c_str());
        return kClientError;
    }
    return kClientSuccess;
}

std::string VpnClient::GetDefaultRouting() {
    std::string def_conf;
    config.Get("route", "def_routing", def_conf);
    return def_conf;
}

}  // namespace client

}  // namespace lego
