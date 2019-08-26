#include "network/bootstrap.h"

#include "common/split.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "common/encode.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "network/universal_manager.h"
#include "network/universal.h"

namespace lego {

namespace network {

Bootstrap* Bootstrap::Instance() {
    static Bootstrap ins;
    return &ins;
}

int Bootstrap::Init(common::Config& config) {
    std::string bootstrap;
    if (!config.Get("lego", "bootstrap", bootstrap) || bootstrap.empty()) {
        NETWORK_ERROR("config has no lego bootstrap info.");
        return kNetworkError;
    }

    root_bootstrap_.clear();
    node_bootstrap_.clear();
    common::Split split(bootstrap.c_str(), ',', bootstrap.size());
    for (uint32_t i = 0; i < split.Count(); ++i) {
        common::Split field_split(split[i], ':', split.SubLen(i));
        if (field_split.Count() != 3) {
            continue;
        }
        security::PrivateKey prikey;
        security::PublicKey pubkey(prikey);
        auto pubkey_ptr = std::make_shared<security::PublicKey>(pubkey);
        lego::dht::DhtKeyManager root_dht_key(
                kUniversalNetworkId,
                common::GlobalInfo::Instance()->country(),
                std::string(field_split[0], field_split.SubLen(0)));
        lego::dht::DhtKeyManager node_dht_key(
                kNodeNetworkId,
                common::GlobalInfo::Instance()->country(),
                std::string(field_split[0], field_split.SubLen(0)));
        root_bootstrap_.push_back(std::make_shared<lego::dht::Node>(
                std::string(field_split[0], field_split.SubLen(0)),
                root_dht_key.StrKey(),
                std::string(field_split[1], field_split.SubLen(1)),
                lego::common::StringUtil::ToUint16(field_split[2]),
                pubkey_ptr));
        node_bootstrap_.push_back(std::make_shared<lego::dht::Node>(
                std::string(field_split[0], field_split.SubLen(0)),
                node_dht_key.StrKey(),
                std::string(field_split[1], field_split.SubLen(1)),
                lego::common::StringUtil::ToUint16(field_split[2]),
                pubkey_ptr));
        NETWORK_INFO("bootstrap[%s][%d][%s][%s][%s]",
                field_split[0], field_split.SubLen(0), field_split[1], field_split[2],
                common::Encode::HexEncode(root_dht_key.StrKey()).c_str());
    }

    if (root_bootstrap_.empty() || node_bootstrap_.empty()) {
        return kNetworkError;
    }
    return kNetworkSuccess;
}

std::vector<dht::NodePtr> Bootstrap::GetNetworkBootstrap(
        uint32_t network_id,
        uint32_t count) {
    auto tmp_dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    std::shared_ptr<Uniersal> universal_dht = std::dynamic_pointer_cast<Uniersal>(tmp_dht);
    assert(universal_dht);
    auto nodes = universal_dht->LocalGetNetworkNodes(
            network_id,
            std::numeric_limits<uint8_t>::max(),
            count);
    if (!nodes.empty()) {
        return nodes;
    }

    nodes = universal_dht->RemoteGetNetworkNodes(network_id, count);
    return nodes;
}

}  // namespace network

}  // namespace lego
