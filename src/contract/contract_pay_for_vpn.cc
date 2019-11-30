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
    if (tx_info.type() != common::kConsensusPayForCommonVpn) {
        return kContractSuccess;
    }

    if (tx_info.to_add()) {
        return kContractSuccess;
    }

    uint64_t day_msec = 24llu * 3600llu * 1000llu;
    uint64_t pay_day_timestamp = block_item.timestamp() / day_msec;
    
    std::lock_guard<std::mutex> guard(payfor_all_map_mutex_);
    auto all_iter = payfor_all_map_.find(tx_info.from());
    if (all_iter == payfor_all_map_.end()) {
        PayInfo pay_info;
        pay_info.day_timestamp = pay_day_timestamp;
        pay_info.amount = tx_info.amount();
        pay_info.height = block_item.height();
        uint64_t use_day = tx_info.amount() / common::kVpnVipMinPayfor;
        pay_info.end_day_timestamp = pay_day_timestamp + use_day;
        payfor_all_map_[tx_info.from()] = pay_info;
    } else {
        if (all_iter->second.height > block_item.height()) {
            return;
        }
        all_iter->second.day_timestamp = pay_day_timestamp;
        all_iter->second.amount = tx_info.amount();
        all_iter->second.height = block_item.height();
        uint64_t use_day = tx_info.amount() / common::kVpnVipMinPayfor;
        all_iter->second.end_day_timestamp = pay_day_timestamp + use_day;
    }
    return kContractSuccess;
}

int PayforVpn::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int PayforVpn::Execute(bft::TxItemPtr& tx_item) {
    if (tx_item->bft_type != common::kConsensusPayForCommonVpn) {
        return kContractError;
    }

    if (tx_item->add_to_acc_addr) {
        return kContractSuccess;
    }

    std::lock_guard<std::mutex> guard(payfor_all_map_mutex_);
    auto all_iter = payfor_all_map_.find(tx_item->from_acc_addr);
    if (all_iter == payfor_all_map_.end()) {
        return kContractSuccess;
    }

    auto now_day_timestamp = common::TimeUtils::TimestampDays();
    if (all_iter->second.end_day_timestamp > now_day_timestamp) {
        CONTRACT_ERROR("user[%s] vpn pay for[%s] prev paied not end.[%llu] now[%llu]",
                common::Encode::HexEncode(tx_item->from_acc_addr).c_str(),
                common::Encode::HexEncode(tx_item->to_acc_addr).c_str(),
                all_iter->second.end_day_timestamp,
                now_day_timestamp);
        return kContractError;
    }
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
