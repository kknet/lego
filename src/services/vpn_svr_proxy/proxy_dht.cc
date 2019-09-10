#include "services/vpn_svr_proxy/proxy_dht.h"

#include "common/global_info.h"
#include "common/country_code.h"
#include "security/ecdh_create_key.h"
#include "security/schnorr.h"
#include "security/aes.h"
#include "security/public_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "services/proto/service_proto.h"
#include "services/proto/service.pb.h"
#include "services/vpn_svr_proxy/proxy_utils.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"
#include "services/account_with_secret.h"

namespace lego {

namespace vpn {

ProxyDht::ProxyDht(
        transport::TransportPtr& transport,
        dht::NodePtr& local_node)
        : BaseDht(transport, local_node) {
    srand(time(NULL));
}

ProxyDht::~ProxyDht() {}

void ProxyDht::HandleMessage(transport::protobuf::Header& msg) {
    if (msg.type() != common::kServiceMessage) {
        return BaseDht::HandleMessage(msg);
    }

    service::protobuf::ServiceMessage svr_msg;
    if (!svr_msg.ParseFromString(msg.data())) {
        PROXY_ERROR("service::protobuf::ServiceMessage ParseFromString failed!");
        return;
    }

    if (svr_msg.has_vpn_req()) {
        HandleGetSocksRequest(msg, svr_msg);
    }
}

int ProxyDht::CheckSign(const service::protobuf::GetVpnInfoRequest& vpn_req) {
    if (!vpn_req.has_sign_challenge() || !vpn_req.has_sign_response()) {
        PROXY_ERROR("backup has no sign");
        return kProxyError;
    }

    auto sign = security::Signature(vpn_req.sign_challenge(), vpn_req.sign_response());
    auto sha128 = common::Hash::Hash128(vpn_req.pubkey());
    security::PublicKey pubkey(vpn_req.pubkey());
    if (!security::Schnorr::Instance()->Verify(sha128, sign, pubkey)) {
        PROXY_ERROR("check signature error!");
        return kProxyError;
    }
    return kProxySuccess;
}

int ProxyDht::ResetUserUseTimer(const service::protobuf::GetVpnInfoRequest& vpn_req) {
    auto account_addr = network::GetAccountAddressByPublicKey(vpn_req.pubkey());
    std::lock_guard<std::mutex> guard(account_vpn_use_map_mutex_);
    auto iter = account_vpn_use_map_.find(account_addr);
    if (iter == account_vpn_use_map_.end()) {
        account_vpn_use_map_[account_addr] = std::make_shared<AccountVpnUseInfo>(
                vpn_req.pubkey(),
                vpn_req.sign_challenge(),
                vpn_req.sign_response());
        return kProxyError;
    }

    double duration = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - iter->second->prev_time).count();
    if (duration <= 30000) {
        iter->second->pre_duration += std::chrono::milliseconds(
                static_cast<uint32_t>(duration));
    }

    if (iter->second->pre_duration.count() >= kStakingPeriod) {
        std::string gid;
        client::TransactionClient::Instance()->Transaction(
                account_addr,
                (std::rand() % 10 + 1),
                gid);
        iter->second->pre_duration = std::chrono::milliseconds(0);
    }
    iter->second->prev_time = std::chrono::steady_clock::now();
    return kProxySuccess;
}

void ProxyDht::HandleGetSocksRequest(
        transport::protobuf::Header& msg,
        service::protobuf::ServiceMessage& src_svr_msg) {
    if (!src_svr_msg.has_vpn_req()) {
        return;
    }

    if (src_svr_msg.vpn_req().heartbeat()) {
        if (!CheckDestination(msg.des_dht_key(), false)) {
            SendToClosestNode(msg);
            return;
        }

        if (CheckSign(src_svr_msg.vpn_req()) != kProxySuccess) {
            return;
        }

        ResetUserUseTimer(src_svr_msg.vpn_req());
        return;
    }

    uint16_t route_port = 0;
    uint16_t server_port = 0;
    ShadowsocksProxy::Instance()->GetShadowsocks(route_port, server_port);
    service::protobuf::ServiceMessage svr_msg;
    auto vpn_res = svr_msg.mutable_vpn_res();
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    vpn_res->set_ip(uni_dht->local_node()->public_ip);
    vpn_res->set_svr_port(server_port);
    vpn_res->set_route_port(route_port);
    auto peer_ptr = service::AccountWithSecret::Instance()->NewPeer(
            src_svr_msg.vpn_req().pubkey(),
            src_svr_msg.vpn_req().method());
    if (peer_ptr == nullptr) {
        return;
    }

    vpn_res->set_secnum(peer_ptr->sec_num);
    vpn_res->set_pubkey(security::Schnorr::Instance()->str_pubkey());
    vpn_res->set_country(common::global_code_to_country_map[
            common::GlobalInfo::Instance()->country()]);
    transport::protobuf::Header res_msg;
    service::ServiceProto::CreateGetVpnInfoRes(local_node(), svr_msg, msg, res_msg);
    network::Route::Instance()->Send(res_msg);
}

}  // namespace vpn

}  // namespace lego
