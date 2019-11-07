#include "contract/contract_vpn_svr_bandwidth.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int VpnSvrBandwidth::InitWithAttr(uint64_t block_height, bft::protobuf::TxInfo& tx_info) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string attr_key = (common::kIncreaseVpnBandwidth + "_" +
            tx_info.to() + "_" + now_day_timestamp);
    std::string attr_val;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == attr_key) {
            attr_val = tx_info.attr(i).value();
            break;
        }
    }
    
    if (attr_val.empty()) {
        return kContractSuccess;
    }

    uint32_t bandwidth = 0;
    try {
        bandwidth = common::StringUtil::ToUint32(attr_val);
    } catch (...) {
        return kContractSuccess;
    }

    if (tx_info.to_add()) {
        std::string one_day_all = kToUseBandwidthOneDay + "_" + now_day_timestamp;
        std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
        auto all_iter = bandwidth_all_map_.find(one_day_all);
        if (all_iter == bandwidth_all_map_.end()) {
            bandwidth_all_map_.clear();
            bandwidth_all_map_[one_day_all] = bandwidth;
        } else {
            all_iter->second += bandwidth;
        }
    }
    return kContractSuccess;
}

int VpnSvrBandwidth::GetAttrWithKey(const std::string& key, std::string& value) {
    std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
    auto all_iter = bandwidth_all_map_.find(key);
    if (all_iter == bandwidth_all_map_.end()) {
        value = "0";
    } else {
        value = std::to_string(all_iter->second);
    }
    return kContractSuccess;
}

int VpnSvrBandwidth::Execute(bft::TxItemPtr& tx_item) {
//     auto iter = attr_map.find(common::kIncreaseVpnBandwidth);
//     if (iter != attr_map.end()) {
//         return kContractSuccess;
//     }
// 
//     std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
//     std::string attr_key = common::kIncreaseVpnBandwidth + "_" + to + "_" + now_day_timestamp;
//     {
//         std::lock_guard<std::mutex> guard(bandwidth_map_mutex_);
//         auto sum_iter = bandwidth_map_.find(attr_key);
//         if (sum_iter == bandwidth_map_.end()) {
//             bandwidth_map_[attr_key] = common::StringUtil::ToUint32(iter->second);
//             attr_map[attr_key] = common::StringUtil::ToUint32(iter->second);
//         } else {
//             sum_iter->second += common::StringUtil::ToUint32(iter->second);
//             attr_map[attr_key] = sum_iter->second;
//         }
// 
//         std::string rm_key = (common::kIncreaseVpnBandwidth + "_" +
//                 to + "_" + std::to_string(common::TimeUtils::TimestampDays() - 1));
//         auto rm_iter = bandwidth_map_.find(rm_key);
//         if (rm_iter != bandwidth_map_.end()) {
//             bandwidth_map_.erase(rm_iter);
//         }
//     }
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
