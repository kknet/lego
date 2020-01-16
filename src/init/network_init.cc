#include "stdafx.h"
#include "init/network_init.h"

#include <functional>

#include "common/global_info.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "ip/ip_with_country.h"
#include "db/db.h"
#include "block/block_manager.h"
#include "transport/multi_thread.h"
#include "transport/udp/udp_transport.h"
#include "transport/transport_utils.h"
#include "transport/http/http_transport.h"
#include "election/elect_dht.h"
#include "election/proto/elect_proto.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/bootstrap.h"
#include "network/route.h"
#include "bft/bft_manager.h"
#include "bft/proto/bft_proto.h"
#include "bft/basic_bft/transaction/proto/tx_proto.h"
#include "sync/key_value_sync.h"
#include "root_congress/congress_init.h"
#include "init/init_utils.h"

namespace lego {

namespace init {

static const std::string kDefaultConfigPath("./conf/lego.conf");
static const uint32_t kDefaultBufferSize = 1024u * 1024u;

NetworkInit::NetworkInit() {}

NetworkInit::~NetworkInit() {
    test_new_account_tick_.Destroy();
    test_new_elect_tick_.Destroy();
}

int NetworkInit::Init(int argc, char** argv) {
    auto b_time = common::TimeStampMsec();
    // std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        INIT_ERROR("network inited!");
        return kInitError;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        INIT_ERROR("init ip config with args failed!");
        return kInitError;
    }

    std::cout << "init ip country use time: " << (common::TimeStampMsec() - b_time) << std::endl;
    if (InitConfigWithArgs(argc, argv) != kInitSuccess) {
        INIT_ERROR("init config with args failed!");
        return kInitError;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        INIT_ERROR("init global info failed!");
        return kInitError;
    }

    std::cout << "global init use time: " << (common::TimeStampMsec() - b_time) << std::endl;
    if (SetPriAndPubKey("") != kInitSuccess) {
        INIT_ERROR("set node private and public key failed!");
        return kInitError;
    }

    if (InitBlock(conf_) != kInitSuccess) {
        INIT_ERROR("init block failed!");
        return kInitError;
    }
    std::cout << "block init use time: " << (common::TimeStampMsec() - b_time) << std::endl;

    if (InitTransport() != kInitSuccess) {
        INIT_ERROR("init transport failed!");
        return kInitError;
    }

    if (InitHttpTransport() != kInitSuccess) {
        INIT_ERROR("init http transport failed!");
        return kInitError;
    }

    std::cout << "transport init use time: " << (common::TimeStampMsec() - b_time) << std::endl;

    if (InitNetworkSingleton() != kInitSuccess) {
        INIT_ERROR("InitNetworkSingleton failed!");
        return kInitError;
    }
    std::cout << "network init use time: " << (common::TimeStampMsec() - b_time) << std::endl;

    if (InitCommand() != kInitSuccess) {
        INIT_ERROR("InitNetworkSingleton failed!");
        return kInitError;
    }

    std::cout << "command init use time: " << (common::TimeStampMsec() - b_time) << std::endl;
    if (CreateConfitNetwork() != kInitSuccess) {
        INIT_ERROR("CreateConfitNetwork failed!");
        return kInitError;
    }

    std::cout << "conf net init use time: " << (common::TimeStampMsec() - b_time) << std::endl;
    if (InitBft() != kInitSuccess) {
        INIT_ERROR("int bft failed!");
        return kInitError;
    }

    std::cout << "bft init use time: " << (common::TimeStampMsec() - b_time) << std::endl;
    sync::KeyValueSync::Instance();

    test_new_account_tick_.CutOff(
            10ull * 1000ull * 1000ull,
            std::bind(&NetworkInit::CreateNewTx, this));
    test_new_elect_tick_.CutOff(
            7ull * 1000ull * 1000ull,
            std::bind(&NetworkInit::CreateNewElectBlock, this));
    test_start_bft_tick_.CutOff(1000 * 1000, std::bind(&NetworkInit::TestStartBft, this));
    inited_ = true;
    cmd_.Run();
    return kInitSuccess;
}

int NetworkInit::InitBft() {
    bft::BftManager::Instance();
    return kInitSuccess;
}

int NetworkInit::CreateConfitNetwork() {
    uint32_t net_id;
    if (!conf_.Get("lego", "net_id", net_id)) {
        return kInitSuccess;
    }

	if (net_id >= network::kConsensusShardEndNetworkId) {
		// for bussiness network
		return kInitSuccess;
	}

	if (net_id == network::kRootCongressNetworkId) {
		congress_ = std::make_shared<congress::CongressInit>();
		if (!congress_->Init() != congress::kCongressSuccess) {
			INIT_ERROR("init congress failed!");
			return kInitError;
		}
		return kInitSuccess;
	}

	if (elect_mgr_.Join(net_id) != elect::kElectSuccess) {
		INIT_ERROR("join network [%u] failed!", net_id);
		return kInitError;
	}
    return kInitSuccess;
}

int NetworkInit::InitTransport() {
    uint32_t send_buff_size = kDefaultUdpSendBufferSize;
    conf_.Get("lego", "send_buff_size", send_buff_size);
    uint32_t recv_buff_size = kDefaultUdpRecvBufferSize;
    conf_.Get("lego", "recv_buff_size", recv_buff_size);
    assert(send_buff_size > kDefaultBufferSize);
    assert(recv_buff_size > kDefaultBufferSize);
    transport_ = std::make_shared<transport::UdpTransport>(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            send_buff_size,
            recv_buff_size);
    transport::MultiThreadHandler::Instance()->Init(transport_);
    if (transport_->Init() != transport::kTransportSuccess) {
        INIT_ERROR("init udp transport failed!");
        return kInitError;
    }

    if (transport_->Start(false) != transport::kTransportSuccess) {
        INIT_ERROR("start udp transport failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitHttpTransport() {
    http_transport_ = std::make_shared<transport::HttpTransport>();
    if (http_transport_->Init() != transport::kTransportSuccess) {
        INIT_ERROR("init http transport failed!");
        return kInitError;
    }

    if (http_transport_->Start(false) != transport::kTransportSuccess) {
        INIT_ERROR("start http transport failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitCommand() {
    bool first_node = false;
    if (!conf_.Get("lego", "first_node", first_node)) {
        INIT_ERROR("get conf lego first_node failed!");
        return kInitError;
    }

    bool show_cmd = false;
    if (!conf_.Get("lego", "show_cmd", show_cmd)) {
        INIT_ERROR("get conf lego show_cmd failed!");
        return kInitError;
    }

    if (!cmd_.Init(first_node, show_cmd)) {
        INIT_ERROR("init command failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitNetworkSingleton() {
    if (network::Bootstrap::Instance()->Init(conf_) != network::kNetworkSuccess) {
        INIT_ERROR("init bootstrap failed!");
        return kInitError;
    }

    if (network::UniversalManager::Instance()->CreateUniversalNetwork(
            conf_,
            transport_) != network::kNetworkSuccess) {
        INIT_ERROR("create universal network failed!");
        return kInitError;
    }

    if (network::UniversalManager::Instance()->CreateNodeNetwork(
            conf_,
            transport_) != network::kNetworkSuccess) {
        INIT_ERROR("create node network failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::InitConfigWithArgs(int argc, char** argv) {
    common::ParserArgs parser_arg;
    if (ParseParams(argc, argv, parser_arg) != kInitSuccess) {
        INIT_ERROR("parse params failed!");
        return kInitError;
    }

    if (parser_arg.Has("h")) {
        cmd_.Help();
        exit(0);
    }

    if (parser_arg.Has("v")) {
        std::string version_info = common::GlobalInfo::Instance()->GetVersionInfo();
        std::cout << "lego version: " << version_info << std::endl;
        exit(0);
    }

    parser_arg.Get("c", config_path_);
    if (config_path_.empty()) {
        config_path_ = kDefaultConfigPath;
    }

    if (!conf_.Init(config_path_.c_str())) {
        INIT_ERROR("init config file failed: %s", config_path_.c_str());
        return kInitError;
    }

    if (ResetConfig(parser_arg) != kInitSuccess) {
        INIT_ERROR("reset config with arg parser failed!");
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::ResetConfig(common::ParserArgs& parser_arg) {
        std::string db_path;
    if (parser_arg.Get("d", db_path) == common::kParseSuccess) {
        if (!conf_.Set("db", "path", db_path)) {
            INIT_ERROR("set config failed [db][path][%s]", db_path.c_str());
            return kInitError;
        }
    }
    std::string country;
    parser_arg.Get("o", country);
    if (!country.empty()) {
        if (!conf_.Set("lego", "country", country)) {
            INIT_ERROR("set config failed [node][country][%s]", country.c_str());
            return kInitError;
        }
    }

    std::string local_ip;
    parser_arg.Get("a", local_ip);
    if (!local_ip.empty()) {
        if (!conf_.Set("lego", "local_ip", local_ip)) {
            INIT_ERROR("set config failed [node][local_ip][%s]", local_ip.c_str());
            return kInitError;
        }
    }
    uint16_t local_port = 0;
    if (parser_arg.Get("l", local_port) == common::kParseSuccess) {
        if (!conf_.Set("lego", "local_port", local_port)) {
            INIT_ERROR("set config failed [node][local_port][%d]", local_port);
            return kInitError;
        }
    }

    int first = 0;
    if (parser_arg.Get("f", first) == common::kParseSuccess) {
        bool first_node = false;
        if (first == 1) {
            first_node = true;
        }

        if (!conf_.Set("lego", "first_node", first_node)) {
            INIT_ERROR("set config failed [node][first_node][%d]", first_node);
            return kInitError;
        }
    }

    std::string network_ids;
    if (parser_arg.Get("n", network_ids) == common::kParseSuccess) {
        if (!conf_.Set("lego", "net_ids", network_ids)) {
            INIT_ERROR("set config failed [node][net_id][%s]", network_ids.c_str());
            return kInitError;
        }
    }

    std::string peer;
    parser_arg.Get("p", peer);
    if (!peer.empty()) {
        if (!conf_.Set("lego", "bootstrap", peer)) {
            INIT_ERROR("set config failed [node][bootstrap][%s]", peer.c_str());
            return kInitError;
        }
    }

    std::string id;
    parser_arg.Get("i", id);
    if (!id.empty()) {
        if (!conf_.Set("lego", "id", id)) {
            INIT_ERROR("set config failed [node][id][%s]", peer.c_str());
            return kInitError;
        }
    }

    int show_cmd = 1;
    if (parser_arg.Get("g", show_cmd) == common::kParseSuccess) {
        if (!conf_.Set("lego", "show_cmd", show_cmd == 1)) {
            INIT_ERROR("set config failed [node][show_cmd][%d]", show_cmd);
            return kInitError;
        }
    }

    int vpn_vip_level = 0;
    if (parser_arg.Get("V", vpn_vip_level) == common::kParseSuccess) {
        if (!conf_.Set("lego", "vpn_vip_level", vpn_vip_level)) {
            INIT_ERROR("set config failed [node][vpn_vip_level][%d]", vpn_vip_level);
            return kInitError;
        }
    }

    std::string log_path;
    if (parser_arg.Get("L", log_path) != common::kParseSuccess) {
        log_path = "log/lego.log";
    }

    if (!conf_.Set("log", "path", log_path)) {
        INIT_ERROR("set config failed [log][log_path][%s]", log_path.c_str());
        return kInitError;
    }
    return kInitSuccess;
}

int NetworkInit::ParseParams(int argc, char** argv, common::ParserArgs& parser_arg) {
    parser_arg.AddArgType('h', "help", common::kNoValue);
    parser_arg.AddArgType('g', "show_cmd", common::kMaybeValue);
    parser_arg.AddArgType('p', "peer", common::kMaybeValue);
    parser_arg.AddArgType('f', "first_node", common::kMaybeValue);
    parser_arg.AddArgType('l', "local_port", common::kMaybeValue);
    parser_arg.AddArgType('a', "local_ip", common::kMaybeValue);
    parser_arg.AddArgType('o', "country_code", common::kMaybeValue);
    parser_arg.AddArgType('n', "network", common::kMaybeValue);
    parser_arg.AddArgType('c', "config_path", common::kMaybeValue);
    parser_arg.AddArgType('d', "db_path", common::kMaybeValue);
    parser_arg.AddArgType('v', "version", common::kNoValue);
    parser_arg.AddArgType('L', "log_path", common::kMaybeValue);
    parser_arg.AddArgType('i', "id", common::kMaybeValue);
    parser_arg.AddArgType('V', "vpn_vip_level", common::kMaybeValue);

    std::string tmp_params = "";
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) == 0) {
            tmp_params += static_cast<char>(31);
        }
        else {
            tmp_params += argv[i];
        }
        tmp_params += " ";
    }

    std::string err_pos;
    if (parser_arg.Parse(tmp_params, err_pos) != common::kParseSuccess) {
        INIT_ERROR("parse params failed!");
        return kInitError;
    }
    return kInitSuccess;
}

void NetworkInit::CreateNewTx() {
    return;
    if (!common::GlobalInfo::Instance()->config_first_node()) {
        return;
    }

    if (!ec_block_ok_) {
        test_new_account_tick_.CutOff(
                1000 * 1000,
                std::bind(&NetworkInit::CreateNewTx, this));
        return;
    }
    auto btime = common::TimeStampMsec();
    for (uint32_t i = 0; i < 1; ++i) {
        transport::protobuf::Header msg;
        auto dht = network::DhtManager::Instance()->GetDht(4);
        if (dht->readonly_dht()->size() >= 2) {
            static uint64_t gid = 0;
            ++gid;
            uint64_t rand_num = 0;
            bft::TxProto::CreateTxRequest(
                    dht->local_node(),
                    std::to_string(gid),
                    rand_num,
                    msg);
            network::Route::Instance()->Send(msg);
            network::Route::Instance()->SendToLocal(msg);
        }
    }
    test_new_account_tick_.CutOff(
            kTestCreateAccountPeriod,
            std::bind(&NetworkInit::CreateNewTx, this));
}

void NetworkInit::TestStartBft() {
	if (common::GlobalInfo::Instance()->config_local_ip() != "139.59.47.229") {
		return;
	}

    if (ec_block_ok_) {
        bft::BftManager::Instance()->StartBft(bft::kTransactionPbftAddress, "", 4, 0);
    }
    test_start_bft_tick_.CutOff(100 * 1000, std::bind(&NetworkInit::TestStartBft, this));
}

void NetworkInit::CreateNewElectBlock() {
    // for test
    if (common::GlobalInfo::Instance()->config_local_ip() != "139.59.47.229") {
        return;
    }

    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(network::GetConsensusShardNetworkId(""));
    if (!dht) {
        assert(false);
		std::cout << "create ec block failed:  " << common::GlobalInfo::Instance()->config_local_ip() << std::endl;
		return;
    }
    elect::ElectProto::CreateElectBlock(dht->local_node(), msg);
    if (!msg.has_data()) {
        test_new_elect_tick_.CutOff(
                1000 * 1000,
                std::bind(&NetworkInit::CreateNewElectBlock, this));
        return;
    }
    network::Route::Instance()->Send(msg);
    network::Route::Instance()->SendToLocal(msg);
    ec_block_ok_ = true;
    test_new_elect_tick_.CutOff(
            kTestNewElectPeriod,
            std::bind(&NetworkInit::CreateNewElectBlock, this));
}

int NetworkInit::SetPriAndPubKey(const std::string&) {
    std::string prikey("");
    conf_.Get("lego", "prikey", prikey) || prikey.empty();
    prikey = common::Encode::HexDecode(prikey);
    std::string private_key = common::Encode::HexDecode(prikey);
    std::shared_ptr<security::PrivateKey> prikey_ptr{ nullptr };
    if (!prikey.empty()) {
        security::PrivateKey tmp_prikey(prikey);
        prikey_ptr = std::make_shared<security::PrivateKey>(tmp_prikey);
    } else {
        security::PrivateKey tmp_prikey;
        prikey_ptr = std::make_shared<security::PrivateKey>(tmp_prikey);
    }
    security::PublicKey pubkey(*(prikey_ptr.get()));
    auto pubkey_ptr = std::make_shared<security::PublicKey>(pubkey);
    security::Schnorr::Instance()->set_prikey(prikey_ptr);
    security::Schnorr::Instance()->set_pubkey(pubkey_ptr);

    std::string pubkey_str;
    pubkey.Serialize(pubkey_str);
    std::string account_id = network::GetAccountAddressByPublicKey(pubkey_str);
    common::GlobalInfo::Instance()->set_id(account_id);

    if (prikey.empty()) {
        conf_.Set("lego", "prikey", common::Encode::HexEncode(
                security::Schnorr::Instance()->str_prikey()));
        conf_.Set("lego", "pubkey", common::Encode::HexEncode(
                security::Schnorr::Instance()->str_pubkey()));
        std::string account_address = network::GetAccountAddressByPublicKey(
                security::Schnorr::Instance()->str_pubkey());
        common::GlobalInfo::Instance()->set_id(account_address);
        conf_.Set("lego", "id", common::Encode::HexEncode(
                common::GlobalInfo::Instance()->id()));
        conf_.DumpConfig(config_path_);
        std::string gid;
    }
    return kInitSuccess;
}

int NetworkInit::InitBlock(const common::Config& conf) {
    std::string db_path;
    conf.Get("db", "path", db_path);
    auto st = db::Db::Instance()->Init(db_path);
    if (!st) {
        INIT_ERROR("init db[%s] failed!", db_path.c_str());
        return kInitError;
    }

    std::cout << "init db ok." << std::endl;
    common::Config tmp_conf = conf;
    if (block::BlockManager::Instance()->Init(tmp_conf) != block::kBlockSuccess) {
        INIT_ERROR("init block manager failed!");
        return kInitError;
    }
    return kInitSuccess;
}

}  // namespace init

}  // namespace lego
