#if defined(_WIN32) || defined(_WIN64)
#include "stdafx.h"
#endif

#include "common/global_info.h"

#include "uuid/uuid.h"
#include "common/random.h"
#include "common/hash.h"
#include "common/country_code.h"
#include "common/log.h"

namespace lego {

namespace common {

static const std::string kAccountAddress(Random::RandomString(1024));

GlobalInfo* GlobalInfo::Instance() {
    static GlobalInfo ins;
    return &ins;
}

GlobalInfo::GlobalInfo()
		: id_(kAccountAddress),
	      message_id_(TimeStampMsec()),
	      network_id_(kDefaultTestNetworkShardId) {
    id_string_hash_ = Hash::Hash192(id_);
    id_hash_ = Hash::Hash64(id_);
    gid_hash_ = Hash::Hash256(Random::RandomString(4096u));
}

GlobalInfo::~GlobalInfo() {}

int GlobalInfo::Init(const common::Config& config) {
    if (!config.Get("lego", "local_ip", config_local_ip_)) {
        ERROR("get lego local_ip from config failed.");
        return kCommonError;
    }

    if (!config.Get("lego", "local_port", config_local_port_)) {
        ERROR("get lego local_port from config failed.");
        return kCommonError;
    }

    if (!config.Get("lego", "http_port", http_port_)) {
        http_port_ = 0;
    }

    std::string str_contry;
    if (!config.Get("lego", "country", str_contry) || str_contry.empty()) {
        ERROR("get lego country from config failed.");
        return kCommonError;
    }
    country_ = global_country_map[str_contry];

    if (!config.Get("lego", "first_node", config_first_node_)) {
        ERROR("get lego first_node from config failed.");
        return kCommonError;
    }

    std::string account_id;
    if (!config.Get("lego", "id", account_id) || account_id.empty()) {
        ERROR("get lego id from config failed.");
        return kCommonError;
    }
    set_id(account_id);

    config.Get("lego", "stream_limit", stream_default_limit_);
    return kCommonSuccess;
}

}  // namespace common

}  // namespace lego
