#pragma once

#include <atomic>
#include <string>

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

    uint8_t country() {
        return country_;
    }

    std::string config_local_ip() {
        return config_local_ip_;
    }

    uint16_t config_local_port() {
        return config_local_port_;
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

private:
    GlobalInfo();
    ~GlobalInfo();

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

    DISALLOW_COPY_AND_ASSIGN(GlobalInfo);
};

}  // namespace common

}  // namespace lego
