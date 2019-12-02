#include "stdafx.h"
#include "subscript/subs_consensus.h"

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/user_property_key_define.h"
#include "ip/ip_with_country.h"
#include "security/ecdh_create_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "init/init_utils.h"

namespace lego {

namespace subs {

SubsConsensus::SubsConsensus() {
    network::Route::Instance()->RegisterMessage(
            common::kSubscriptionMessage,
            std::bind(&SubsConsensus::HandleMessage, this, std::placeholders::_1));
}

SubsConsensus::~SubsConsensus() {}

void SubsConsensus::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kSubscriptionMessage) {
        return;
    }

    std::cout << "receive consensus block message." << std::endl;
}

SubsConsensus* SubsConsensus::Instance() {
    static SubsConsensus ins;
    return &ins;
}

int SubsConsensus::Init(int argc, char** argv) {
    std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        SUBS_ERROR("network inited!");
        return kSubsError;
    }

    if (InitConfigWithArgs(argc, argv) != init::kInitSuccess) {
        SUBS_ERROR("init config with args failed!");
        return kSubsError;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        SUBS_ERROR("init ip config with args failed!");
        return kSubsError;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        SUBS_ERROR("init global info failed!");
        return kSubsError;
    }

    if (SetPriAndPubKey("") != init::kInitSuccess) {
        SUBS_ERROR("set node private and public key failed!");
        return kSubsError;
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        SUBS_ERROR("init ecdh create secret key failed!");
        return kSubsError;
    }

    network::DhtManager::Instance();
    network::UniversalManager::Instance();
    network::Route::Instance();
    if (InitTransport() != init::kInitSuccess) {
        SUBS_ERROR("init transport failed!");
        return kSubsError;
    }

    if (InitHttpTransport() != transport::kTransportSuccess) {
        SUBS_ERROR("init http transport failed!");
        return kSubsError;
    }

    if (InitNetworkSingleton() != init::kInitSuccess) {
        SUBS_ERROR("InitNetworkSingleton failed!");
        return kSubsError;
    }

    if (StartSubscription() != kSubsSuccess) {
        return kSubsError;
    }

    if (InitCommand() != init::kInitSuccess) {
        SUBS_ERROR("InitNetworkSingleton failed!");
        return kSubsError;
    }

    std::string gid;
    std::map<std::string, std::string> attrs;
    lego::client::TransactionClient::Instance()->Transaction(
            "",
            0,
            "",
            attrs,
            common::kConsensusCreateAcount,
            gid);
    // check account address valid
    inited_ = true;
    cmd_.Run();
    transport_->Stop();
    network::DhtManager::Instance()->Destroy();
    std::cout << "exit now." << std::endl;
    exit(0);
    return kSubsSuccess;
}

int SubsConsensus::StartSubscription() {
    subs_node_ = std::make_shared<SubsDhtNode>(network::kConsensusSubscription);
    if (subs_node_->Init() != network::kNetworkSuccess) {
        subs_node_ = nullptr;
        SUBS_ERROR("node join network [%u] failed!", network::kConsensusSubscription);
        return kSubsError;
    }

    return kSubsSuccess;
}

}  // namespace vpn

}  // namespace lego
