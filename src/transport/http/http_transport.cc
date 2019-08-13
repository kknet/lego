#include "common/global_info.h"
#include "common/encode.h"
#include "common/hash.h"
#include "db/db.h"
#include "security/schnorr.h"
#include "security/sha256.h"
#include "transport/http/http_transport.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "block/account_manager.h"

namespace lego {

namespace transport {

HttpTransport::HttpTransport() {}
HttpTransport::~HttpTransport() {}

int HttpTransport::Init() {
    if (!http_svr_.is_valid()) {
        return -1;
    }
    return kTransportSuccess;
}

int HttpTransport::Start(bool hold) {
    if (hold) {
        Listen();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&HttpTransport::Listen, this));
        run_thread_->detach();
    }
}

static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;

static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right(std::numeric_limits<uint64_t>::max());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

static void CreateTxRequest(
        const nlohmann::json& data,
        std::string& account_address,
        transport::protobuf::Header& msg) {
    auto prikey = security::PrivateKey(common::Encode::HexDecode(
        data["prikey"].get<std::string>()));
    auto pubkey = security::PublicKey(prikey);
    std::string str_pubkey;
    pubkey.Serialize(str_pubkey);
    auto gid = common::Encode::HexDecode(data["gid"].get<std::string>());
    auto to = common::Encode::HexDecode(data["to"].get<std::string>());
    msg.set_src_dht_key(common::Encode::HexDecode(
            data["src_dht_key"].get<std::string>()));
    account_address = network::GetAccountAddressByPublicKey(str_pubkey);
    uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_rand(0);
    bft_msg.set_status(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft_msg.set_node_id(account_address);
    bft_msg.set_pubkey(str_pubkey);
    bft_msg.set_bft_address(bft::kTransactionPbftAddress);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from_acc_addr(account_address);
    new_tx->set_from_pubkey(str_pubkey);
    new_tx->set_to_acc_addr(to);
    new_tx->set_lego_count(data["amount"].get<uint64_t>());
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    auto hash128 = common::Hash::Hash128(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            prikey,
            pubkey,
            sign)) {
        TRANSPORT_ERROR("leader pre commit signature failed!");
        return;
    }
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("js new account: ") +
            common::Encode::HexEncode(account_address) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}


void HttpTransport::Listen() {
    http_svr_.Get("/http_message", [=](const httplib::Request& req, httplib::Response &res) {
        std::cout << "http get request size: " << req.body.size() << std::endl;
        res.set_content("Hello World!\n", "text/plain");
    });

    http_svr_.Post("/transaction", [&](const httplib::Request &req, httplib::Response &res) {
        std::map<std::string, std::string> params;
        std::string account_address;
        try {
            nlohmann::json json_obj = nlohmann::json::parse(req.body);
            nlohmann::json data = json_obj["data"];
            transport::protobuf::Header msg;
            CreateTxRequest(data, account_address, msg);
            network::Route::Instance()->Send(msg);
            network::Route::Instance()->SendToLocal(msg);
            TRANSPORT_ERROR("js relay by this node ok.");
            std::cout << "js relay by this node ok." << std::endl;
        } catch (std::exception& e) {
            res.status = 400;
            TRANSPORT_ERROR("js relay by this node error.");
            std::cout << "js relay by this node error." << e.what() << std::endl;
            return;
        }
        res.set_content(common::Encode::HexEncode(account_address), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
        return;
    });

    http_svr_.Post("/account_balance", [&](const httplib::Request &req, httplib::Response &res) {
        std::map<std::string, std::string> params;
        std::string account_address;
        try {
            nlohmann::json json_obj = nlohmann::json::parse(req.body);
            auto acc_addr = common::Encode::HexDecode(json_obj["acc_addr"].get<std::string>());
            auto acc_info_ptr = block::AccountManager::Instance()->GetAcountInfo(acc_addr);
            if (acc_info_ptr == nullptr) {
                res.set_content(std::to_string(-1), "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
            } else {
                res.set_content(std::to_string(acc_info_ptr->balance), "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
            }
        } catch (...) {
            res.status = 400;
            TRANSPORT_ERROR("account_balance by this node error.");
            std::cout << "account_balance by this node error." << std::endl;
        }
    });

    http_svr_.Post("/get_transaction", [&](const httplib::Request &req, httplib::Response &res) {
        std::map<std::string, std::string> params;
        std::string account_address;
        try {
            nlohmann::json json_obj = nlohmann::json::parse(req.body);
            std::string tx_gid;
            std::string block_hash;
            if (json_obj.find("tx_gid") != json_obj.end()) {
                auto tx_gid = common::Encode::HexDecode(json_obj["tx_gid"].get<std::string>());
                tx_gid = common::GetTxDbKey(true, tx_gid);
                auto st = db::Db::Instance()->Get(tx_gid, &block_hash);
                if (!st.ok()) {
                    res.set_content("gid not exists", "text/plain");
                    res.set_header("Access-Control-Allow-Origin", "*");
                    return;
                }
            }

            if (json_obj.find("block_hash") != json_obj.end()) {
                block_hash = common::Encode::HexDecode(json_obj["block_hash"].get<std::string>());
            }

            std::string block_data;
            auto st = db::Db::Instance()->Get(block_hash, &block_data);
            if (!st.ok()) {
                res.set_content("block not exists", "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
                return;
            }

            bft::protobuf::Block block;
            if (!block.ParseFromString(block_data)) {
                res.set_content("block error", "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
                return;
            }

            nlohmann::json res_json;
            res_json["block_height"] = block.height();
            res_json["block_hash"] = common::Encode::HexEncode(block.hash());
            res_json["prev_hash"] = common::Encode::HexEncode(block.tx_block().prehash());
            res_json["transaction_size"] = block.tx_block().tx_list_size();
            auto tx_list_res = res_json["tx_list"];
            auto tx_list = block.tx_block().tx_list();
            for (int32_t i = 0; i < tx_list.size(); ++i) {
                res_json["tx_list"][i]["tx_gid"] = common::Encode::HexEncode(tx_list[i].gid());
                res_json["tx_list"][i]["from"] = common::Encode::HexEncode(tx_list[i].from());
                res_json["tx_list"][i]["to"] = common::Encode::HexEncode(tx_list[i].to());
                res_json["tx_list"][i]["amount"] = tx_list[i].amount();
            }
            res.set_content(res_json.dump(), "text/plain");
            res.set_header("Access-Control-Allow-Origin", "*");
        } catch (...) {
            res.status = 400;
            TRANSPORT_ERROR("account_balance by this node error.");
            std::cout << "account_balance by this node error." << std::endl;
        }
    });

    http_svr_.set_error_handler([](const httplib::Request&, httplib::Response &res) {
        const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    if (!http_svr_.listen(
            common::GlobalInfo::Instance()->config_local_ip().c_str(),
            common::GlobalInfo::Instance()->http_port())) {
        assert(false);
        exit(1);
    }
}

void HttpTransport::Stop() {
    http_svr_.stop();
}

int HttpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::SendToLocal(transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::GetSocket() {
    assert(false);
    return kTransportSuccess;
}

}  // namespace transport

}  // namespace lego
