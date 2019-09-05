#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "ip/ip_with_country.h"
#include "security/ecdh_create_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "services/vpn_server/vpn_server.h"
#include "services/vpn_svr_proxy/proxy_utils.h"

namespace lego {

namespace vpn {

ShadowsocksProxy::ShadowsocksProxy() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&ShadowsocksProxy::HandleMessage, this, std::placeholders::_1));
//     tick_status_.CutOff(
//             kCheckVpnServerStatusPeriod,
//             std::bind(&ShadowsocksProxy::CheckVpnStatus, this));
}

ShadowsocksProxy::~ShadowsocksProxy() {}

void ShadowsocksProxy::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kServiceMessage) {
        return;
    }

    auto dht = network::Route::Instance()->GetDht(header.des_dht_key(), header.universal());
    assert(dht);
    dht->HandleMessage(header);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("socks proxy", header);
}

ShadowsocksProxy* ShadowsocksProxy::Instance() {
    static ShadowsocksProxy ins;
    return &ins;
}

int ShadowsocksProxy::Init(int argc, char** argv) {
    std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        PROXY_ERROR("network inited!");
        return kProxyError;
    }

//     std::string cmd = common::StringUtil::Format(
//             "ps -ef | grep gpgk | awk -F' ' '{print $2}' | xargs kill -9");
//     auto res = system(cmd.c_str());
//     if (RunCommand(cmd, "") != kProxySuccess) {
//         PROXY_ERROR("run cmd [%s] failed!", cmd.c_str());
//         return kProxyError;
//     }

    if (InitConfigWithArgs(argc, argv) != kProxySuccess) {
        PROXY_ERROR("init config with args failed!");
        return kProxySuccess;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        PROXY_ERROR("init ip config with args failed!");
        return kProxySuccess;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        PROXY_ERROR("init global info failed!");
        return kProxyError;
    }

    if (SetPriAndPubKey("") != kProxySuccess) {
        PROXY_ERROR("set node private and public key failed!");
        return kProxyError;
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        PROXY_ERROR("init ecdh create secret key failed!");
        return kProxyError;
    }

    if (InitTransport() != kProxySuccess) {
        PROXY_ERROR("init transport failed!");
        return kProxyError;
    }

    if (InitNetworkSingleton() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    if (StartShadowsocks() != kProxySuccess) {
        PROXY_ERROR("start shadowsocks failed!");
        return kProxyError;
    }

    if (CreateVpnProxyNetwork() != kProxySuccess) {
        PROXY_ERROR("create vpn proxy network failed!");
        return kProxyError;
    }

    if (InitCommand() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    std::string gid;
    client::TransactionClient::Instance()->Transaction("", 0, gid);
    inited_ = true;
    cmd_.Run();
    return kProxySuccess;
}

ShadowsocksConfPtr ShadowsocksProxy::GetShadowsocks() {
    if (socks_vec_.empty()) {
        return nullptr;
    }

    srand(time(NULL));
    auto rand_idx = std::rand() % socks_vec_.size();
    return socks_vec_[rand_idx];
}

int ShadowsocksProxy::StartShadowsocks() {
    if (VpnServer::Init(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port() + 31,
            "password",
            "",
            "aes-128-cfb") != kVpnsvrSuccess) {
        return kProxyError;
    }
    return kProxySuccess;
    /*
    for (uint32_t i = 0; i < kEncryptTypeVec.size(); ++i) {
        ShadowsocksConfPtr socks_conf = std::make_shared<ShadowsocksConf>();
        socks_conf->method = kEncryptTypeVec[i].first;
        socks_conf->port = kEncryptTypeVec[i].second;
        socks_conf->mode = kMode;
        socks_conf->passwd = common::Encode::HexEncode(common::Random::RandomString(32));
        socks_conf->timeout = 60;
        if (!conf_.Get("lego", "vpn_bin_path", vpn_bin_path_) || vpn_bin_path_.empty()) {
            PROXY_ERROR("get vpn bin path failed.");
            return kProxyError;
        }

        std::string cmd = common::StringUtil::Format(
                "nohup %s -s %s -p %d -k %s -m %s -t %d -u &",
                vpn_bin_path_.c_str(),
                common::GlobalInfo::Instance()->config_local_ip().c_str(),
                socks_conf->port,
                socks_conf->passwd.c_str(),
                socks_conf->method.c_str(),
                socks_conf->timeout);
        if (RunCommand(cmd, "running from") != kProxySuccess) {
            PROXY_ERROR("run cmd [%s] failed!", cmd.c_str());
            return kProxyError;
        }
        socks_vec_.push_back(socks_conf);
        PROXY_INFO("run cmd [%s] succ!", cmd.c_str());
    }

    return kProxySuccess;
    */
}

int ShadowsocksProxy::RunCommand(const std::string& cmd, const std::string& succ_res) {
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp == NULL) {
        PROXY_ERROR("run cmd[%s] failed!", cmd.c_str());
        return kProxyError;
    }

    if (succ_res.empty()) {
        return kProxySuccess;
    }

    int fd = fileno(fp);
    auto flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
    std::this_thread::sleep_for(std::chrono::microseconds(1000000ull));
    char buff[1024] = { 0 };
    bool succ_find = false;
    std::string res_str;
    while (fgets(buff, sizeof(buff), fp)) {
        std::string tmp_res(buff);
        if (tmp_res.empty()) {
            break;
        }
        res_str += tmp_res;
        auto rel = strstr(tmp_res.c_str(), succ_res.c_str());
        if (rel != nullptr) {
            succ_find = true;
            break;
        }
    }
    pclose(fp);

    if (succ_find) {
        return kProxySuccess;
    }
    PROXY_ERROR("run cmd[%s] failed[%s]", cmd.c_str(), res_str.c_str());
    return kProxyError;
}

void ShadowsocksProxy::CheckVpnStatus() {
    {
        for (uint32_t i = 0; i < socks_vec_.size(); ++i) {
            auto socks_conf = socks_vec_[i];
            if (!CheckVpnExists(socks_conf->passwd)) {
                auto cmd = common::StringUtil::Format(
                        "nohup %s -s %s -p %d -k %s -m %s -t %d -u &",
                        vpn_bin_path_.c_str(),
                        common::GlobalInfo::Instance()->config_local_ip().c_str(),
                        socks_conf->port,
                        socks_conf->passwd.c_str(),
                        socks_conf->method.c_str(),
                        socks_conf->timeout);
                if (RunCommand(cmd, "running from") != kProxySuccess) {
                    PROXY_ERROR("run cmd [%s] failed!", cmd.c_str());
                }
            }
        }
    }
    tick_status_.CutOff(
            kCheckVpnServerStatusPeriod,
            std::bind(&ShadowsocksProxy::CheckVpnStatus, this));
}

int ShadowsocksProxy::CreateVpnProxyNetwork() {
    vpn_proxy_ = std::make_shared<VpnProxyNode>(network::kVpnNetworkId);
    if (vpn_proxy_->Init() != network::kNetworkSuccess) {
        vpn_proxy_ = nullptr;
        PROXY_ERROR("node join network [%u] failed!", network::kVpnNetworkId);
        return kProxyError;
    }

    return kProxySuccess;
}

bool ShadowsocksProxy::CheckVpnExists(const std::string& passwd) {
    std::string cmd = common::StringUtil::Format("ps -ef | grep %s", passwd.c_str());
    std::string vpn_bin_path;
    if (!conf_.Get("lego", "vpn_bin_path", vpn_bin_path) || vpn_bin_path.empty()) {
        PROXY_ERROR("get vpn bin path failed.");
        return true;
    }
    for (uint32_t i = 0; i < 3; ++i) {
        if (RunCommand(cmd, vpn_bin_path) != kProxySuccess) {
            std::this_thread::sleep_for(std::chrono::microseconds(1000000ull));
            continue;
        }
        return true;
    }
    return false;
}

}  // namespace vpn

}  // namespace lego
