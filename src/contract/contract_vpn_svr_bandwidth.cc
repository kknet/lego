#include "contract/contract_vpn_svr_bandwidth.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int VpnSvrBandwidth::InitWithAttr(
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        const std::map<std::string, std::string>& attr_map) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string attr_key = common::kIncreaseVpnBandwidth + "_" + to + "_" + now_day_timestamp;
    auto iter = attr_map.find(attr_key);
    if (iter == attr_map.end()) {
        return kContractSuccess;
    }

    {
        std::lock_guard<std::mutex> guard(bandwidth_map_mutex_);
        bandwidth_map_.clear();
        bandwidth_map_[attr_key] = common::StringUtil::ToUint32(iter->second);
    }
    return kContractSuccess;
}

int VpnSvrBandwidth::Execute(
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        std::map<std::string, std::string>& attr_map) {
    auto iter = attr_map.find(common::kIncreaseVpnBandwidth);
    if (iter != attr_map.end()) {
        return kContractSuccess;
    }

    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string attr_key = common::kIncreaseVpnBandwidth + "_" + to + "_" + now_day_timestamp;
    {
        std::lock_guard<std::mutex> guard(bandwidth_map_mutex_);
        auto sum_iter = bandwidth_map_.find(attr_key);
        if (sum_iter == bandwidth_map_.end()) {
            bandwidth_map_[attr_key] = common::StringUtil::ToUint32(iter->second);
            attr_map[attr_key] = common::StringUtil::ToUint32(iter->second);
        } else {
            sum_iter->second += common::StringUtil::ToUint32(iter->second);
            attr_map[attr_key] = sum_iter->second;
        }

        std::string rm_key = (common::kIncreaseVpnBandwidth + "_" +
                to + "_" + std::to_string(common::TimeUtils::TimestampDays() - 1));
        auto rm_iter = bandwidth_map_.find(rm_key);
        if (rm_iter != bandwidth_map_.end()) {
            bandwidth_map_.erase(rm_iter);
        }
    }
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
