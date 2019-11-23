#pragma once

#include <atomic>
#include <string>
#include <mutex>
#include <cassert>

#include "common/utils.h"
#include "common/hash.h"
#include "common/config.h"

namespace lego {

namespace common {

class GlobalInfo {
public:
    static GlobalInfo* Instance();
    int Init(const common::Config& config);

    uint32_t MessageId() {
        return ++message_id_;
    }

    void set_id(const std::string& id) {
        id_ = id;
        id_string_hash_ = Hash::Hash192(id_);
        id_hash_ = Hash::Hash64(id_);
    }

    const std::string& id() {
        return id_;
    }

    const std::string& id_string_hash() {
        return id_string_hash_;
    }

    uint64_t id_hash() {
        return id_hash_;
    }

    void set_country(uint8_t country) {
        country_ = country;
    }

    uint8_t country() {
        return country_;
    }

    std::string config_local_ip() {
        return config_local_ip_;
    }

    uint16_t config_local_port() {
        return config_local_port_;
    }

    int32_t config_default_stream_limit() {
        return stream_default_limit_;
    }

    void set_config_local_ip(const std::string& ip) {
        config_local_ip_ = ip;
    }

    void set_config_local_port(uint16_t port) {
        config_local_port_ = port;
    }

    uint16_t http_port() {
        return http_port_;
    }

    bool config_first_node() {
        return config_first_node_;
    }

    const std::string& GetVersionInfo() {
        return version_info_;
    }

    std::string gid() {
        return gid_hash_ + std::to_string(gid_idx_.fetch_add(1));
    }

	void set_network_id(uint32_t netid) {
		// one node just has only one network role
		std::lock_guard<std::mutex> guard(network_id_set_mutex_);
		if (network_id_ != 0) {
			assert(false);
			return;
		}
		network_id_ = netid;
	}

	uint32_t network_id() {
		return network_id_;
	}

	void set_consensus_shard_count(uint32_t count) {
		consensus_shard_count_ = count;
	}

	uint32_t consensus_shard_count() {
		return consensus_shard_count_;
	}

private:
    GlobalInfo();
    ~GlobalInfo();

	static const uint32_t kDefaultTestNetworkShardId = 4u;

    std::string id_;
    std::atomic<uint32_t> message_id_{ 0 };
    std::string id_string_hash_;
    uint64_t id_hash_{ 0 };
    uint8_t country_{ 0 };
    std::string config_local_ip_;
    uint16_t config_local_port_{ 0 };
    bool config_first_node_{ false };
    std::string version_info_;
    std::string gid_hash_;
    std::atomic<uint64_t> gid_idx_{ 0 };
    uint16_t http_port_{ 0 };
	uint32_t network_id_{ 0 };
	std::mutex network_id_set_mutex_;
	uint32_t consensus_shard_count_{ 0 };
    int32_t stream_default_limit_{ 262144 };

    DISALLOW_COPY_AND_ASSIGN(GlobalInfo);
};

}  // namespace common

}  // namespace lego
