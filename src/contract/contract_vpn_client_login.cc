#include "stdafx.h"
#include "contract/contract_vpn_client_login.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "common/split.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int VpnClientLogin::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info) {
    if (!tx_info.to_add()) {
        return kContractSuccess;
    }

    std::string attr_key;
    std::string attr_val;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key().empty()) {
            attr_key = tx_info.attr(i).key();
            attr_val = tx_info.attr(i).value();
            break;
        }
    }

    if (attr_val.empty()) {
        return kContractSuccess;
    }

    std::map<uint32_t, uint32_t> country_count_map;
    common::Split all_split(attr_val.c_str(), ',', attr_val.size());
    for (int i = 0; i < all_split.Count(); ++i) {
        common::Split item_split(all_split[i], ':', all_split.SubLen(i));
        if (item_split.Count() != 2) {
            continue;
        }
        try {
            country_count_map[common::StringUtil::ToUint32(item_split[0])] =
                    common::StringUtil::ToUint32(item_split[1]);
        } catch (...) {
            continue;
        }
    }

    std::lock_guard<std::mutex> guard(client_login_map_mutex_);
    auto all_iter = client_login_map_.find(attr_key);
    if (all_iter == client_login_map_.end()) {
        client_login_map_[attr_key] = country_count_map;
    } else {
        for (auto iter = country_count_map.begin();
                iter != country_count_map.end(); ++iter) {
            std::map<uint32_t, uint32_t>& tmp_map = all_iter->second;
            auto tmp_find_iter = tmp_map.find(iter->first);
            if (tmp_find_iter == tmp_map.end()) {
                tmp_map[iter->first] = iter->second;
            } else {
                tmp_find_iter->second += iter->second;
            }
        }
    }

    std::string del_day_timestamp = std::to_string(common::TimeUtils::TimestampDays() - 30);
    std::string del_key = common::kVpnClientLoginAttr + del_day_timestamp;
    auto iter = client_login_map_.find(del_key);
    if (iter != client_login_map_.end()) {
        client_login_map_.erase(iter);
    }

    return kContractSuccess;
}

int VpnClientLogin::GetAttrWithKey(const std::string& key, std::string& value) {
    std::lock_guard<std::mutex> guard(client_login_map_mutex_);
    auto all_iter = client_login_map_.find(key);
    if (all_iter == client_login_map_.end()) {
        return kContractError;
    } 

    value = "";
    for (auto iter = all_iter->second.begin(); iter != all_iter->second.end(); ++iter) {
        value += std::to_string(iter->first) + ":" + std::to_string(iter->second) + ",";
    }
    return kContractSuccess;
}

int VpnClientLogin::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
