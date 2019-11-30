#include "stdafx.h"
#include "contract/contract_pay_for_vpn.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int PayforVpn::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
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

    if (tx_info.to_add()) {
        std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
        auto all_iter = bandwidth_all_map_.find(attr_key);
        if (all_iter == bandwidth_all_map_.end()) {
            bandwidth_all_map_[attr_key] = bandwidth;
        } else {
            all_iter->second += bandwidth;
        }
    }
    return kContractSuccess;
}

int PayforVpn::GetAttrWithKey(const std::string& key, std::string& value) {
    std::lock_guard<std::mutex> guard(bandwidth_all_map_mutex_);
    auto all_iter = bandwidth_all_map_.find(key);
    if (all_iter == bandwidth_all_map_.end()) {
        return kContractError;
    } 

    value = std::to_string(all_iter->second);
    return kContractSuccess;
}

int PayforVpn::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
