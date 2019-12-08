#include "stdafx.h"
#include "contract/contract_vpn_svr_bandwidth.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "common/split.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int VpnSvrBandwidth::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info) {
    if (!tx_info.to_add()) {
        return kContractSuccess;
    }

    uint64_t block_day_timestamp = block_item.timestamp() / (24LLU * 3600LLU * 1000LLU);
    {
        std::lock_guard<std::mutex> guard(day_alives_mutex_);
        auto iter = day_alives_.find(block_day_timestamp);
        if (iter != day_alives_.end()) {
            iter->second.insert(tx_info.to());
        } else {
            std::unordered_set<std::string> tmp_set = { tx_info.to() };
            day_alives_[block_day_timestamp] = tmp_set;
        }

        auto del_iter = day_alives_.find(block_day_timestamp - 30);
        if (del_iter != day_alives_.end()) {
            day_alives_.erase(del_iter);
        }
    }


    uint64_t now_timestamp = common::TimeUtils::TimestampDays();
    if (now_timestamp != block_day_timestamp) {
        return kContractSuccess;
    }
    std::string now_day_timestamp = std::to_string(now_timestamp);
    std::string attr_key = (common::kIncreaseVpnBandwidth + "_" +
            common::Encode::HexEncode(tx_info.to()) + "_" + now_day_timestamp);
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

    {
        std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
        auto all_iter = bandwidth_all_map_.find(attr_key);
        if (all_iter == bandwidth_all_map_.end()) {
            bandwidth_all_map_[attr_key] = bandwidth;
        } else {
            all_iter->second += bandwidth;
        }

        std::string del_day = std::to_string(now_timestamp - 2);
        std::string del_attr_key = (common::kIncreaseVpnBandwidth + "_" +
            common::Encode::HexEncode(tx_info.to()) + "_" + del_day);
        auto del_ter = bandwidth_all_map_.find(del_attr_key);
        if (del_ter != bandwidth_all_map_.end()) {
            bandwidth_all_map_.erase(del_ter);
        }
    }

    return kContractSuccess;
}

int VpnSvrBandwidth::GetAttrWithKey(const std::string& key, std::string& value) {
    if (strncmp(
            key.c_str(),
            common::kIncreaseVpnBandwidth.c_str(),
            common::kIncreaseVpnBandwidth.size()) == 0) {
        std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
        auto all_iter = bandwidth_all_map_.find(key);
        if (all_iter == bandwidth_all_map_.end()) {
            return kContractError;
        }

        value = std::to_string(all_iter->second);
        return kContractSuccess;
    }

    if (strncmp(
            key.c_str(),
            common::kActiveUser.c_str(),
            common::kActiveUser.size()) == 0) {
        std::lock_guard<std::mutex> guard(day_alives_mutex_);
        uint64_t now_timestamp = common::TimeUtils::TimestampDays();
        for (int i = 0; i < 30; ++i) {
            auto all_iter = day_alives_.find(now_timestamp - i);
            if (all_iter == day_alives_.end()) {
                return kContractError;
            }

            value += std::to_string(all_iter->second.size()) + ",";
        }
        return kContractSuccess;
    }
    return kContractError;
}

int VpnSvrBandwidth::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
