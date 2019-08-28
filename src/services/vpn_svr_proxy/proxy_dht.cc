#include "services/vpn_svr_proxy/proxy_dht.h"

#include "security/ecdh_create_key.h"
#include "security/schnorr.h"
#include "security/aes.h"
#include "network/route.h"
#include "services/proto/service_proto.h"
#include "services/proto/service.pb.h"
#include "services/vpn_svr_proxy/proxy_utils.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

namespace lego {

namespace vpn {

ProxyDht::ProxyDht(
        transport::TransportPtr& transport,
        dht::NodePtr& local_node)
        : BaseDht(transport, local_node) {}

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

void ProxyDht::HandleGetSocksRequest(
        transport::protobuf::Header& msg,
        service::protobuf::ServiceMessage& src_svr_msg) {
    if (!src_svr_msg.has_vpn_req()) {
        return;
    }

    auto vpn_conf = ShadowsocksProxy::Instance()->GetShadowsocks();
    if (vpn_conf == nullptr) {
        PROXY_ERROR("there is no vpn service started!");
        return;
    }

    service::protobuf::ServiceMessage svr_msg;
    auto vpn_res = svr_msg.mutable_vpn_res();
    vpn_res->set_ip(local_node()->public_ip);
    vpn_res->set_port(vpn_conf->port);
    vpn_res->set_encrypt_type(vpn_conf->method);
    security::PublicKey pubkey;
    if (pubkey.Deserialize(src_svr_msg.vpn_req().pubkey()) != 0) {
        PROXY_ERROR("invalid public key.");
        return;
    }

    // ecdh encrypt vpn password
    std::string sec_key;
    auto res = security::EcdhCreateKey::Instance()->CreateKey(pubkey, sec_key);
    if (res != security::kSecuritySuccess) {
        PROXY_ERROR("create sec key failed!");
        return;
    }

    std::string enc_passwd;
    if (security::Aes::Encrypt(
            vpn_conf->passwd,
            sec_key,
            enc_passwd) != security::kSecuritySuccess) {
        PROXY_ERROR("aes encrypt failed!");
        return;
    }
    vpn_res->set_passwd(enc_passwd);
    vpn_res->set_pubkey(security::Schnorr::Instance()->str_pubkey());
    transport::protobuf::Header res_msg;
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("getted socks", msg);
    service::ServiceProto::CreateGetVpnInfoRes(local_node(), svr_msg, msg, res_msg);
    network::Route::Instance()->Send(res_msg);
    PROXY_ERROR("send res get vpn config info.");
    auto netid = dht::DhtKeyManager::DhtKeyGetNetId(res_msg.des_dht_key());
    std::cout << "send to des network: " << netid << ":" << res_msg.client_handled() << std::endl;
}

}  // namespace vpn

}  // namespace lego
