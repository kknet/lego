#include "client/vpn_client.h"

#include <cassert>

#include "common/hash.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "common/state_lock.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/schnorr.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread.h"
#include "transport/synchro_wait.h"
#include "transport/transport_utils.h"
#include "dht/base_dht.h"
#include "network/network_utils.h"
#include "network/bootstrap.h"
#include "network/universal_manager.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal.h"
#include "client/client_utils.h"
#include "client/proto/client.pb.h"
#include "client/proto/client_proto.h"

namespace lego {

namespace client {

static const uint32_t kDefaultBufferSize = 1024u * 1024u;

VpnClient::VpnClient() {}

VpnClient::~VpnClient() {}

int VpnClient::Init(const std::string& conf) {
    if (!conf_.Init(conf)) {
        CLIENT_ERROR("init config [%s] failed!", conf.c_str());
        return kClientError;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        CLIENT_ERROR("init global info failed!");
        return kClientError;
    }

    if (SetPriAndPubKey("") != kClientSuccess) {
        return kClientError;
    }

    if (InitTransport() != kClientSuccess) {
        return kClientError;
    }

    if (InitNetworkSingleton() != kClientSuccess) {
        return kClientError;
    }
    return kClientSuccess;
}

int VpnClient::GetVpnServerNodes(
        const std::string& country,
        uint32_t count,
        std::vector<VpnServerNodePtr>& nodes) {
    auto dht_nodes = root_dht_->RemoteGetNetworkNodes(
            network::kVpnNetworkId,
            common::global_country_map[country],
            count);
    return GetVpnNodes(dht_nodes, nodes);
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
    transport::SynchroWait::Instance()->Add(msg_id, 500 * 1000, callback, nodes.size());
    state_lock.Wait();
    return kClientSuccess;
}

int VpnClient::InitTransport() {
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
    if (network::Bootstrap::Instance()->Init(conf_) != network::kNetworkSuccess) {
        CLIENT_ERROR("init bootstrap failed!");
        return kClientError;
    }

    network::DhtManager::Instance()->Init();
    network::UniversalManager::Instance()->Init();
    network::Route::Instance()->Init();
    if (network::UniversalManager::Instance()->CreateUniversalNetwork(
            conf_,
            transport_) != network::kNetworkSuccess) {
        CLIENT_ERROR("create universal network failed!");
        return kClientError;
    }
    root_dht_ = std::dynamic_pointer_cast<network::Uniersal>(
            network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId));
    if (root_dht_ == nullptr) {
        assert(root_dht_ != nullptr);
        return kClientError;
    }
    return kClientSuccess;
}

}  // namespace client

}  // namespace lego
