#include "block/account_manager.h"

#include "common/encode.h"
#include "statistics/statistics.h"
#include "contract/contract_manager.h"
#include "db/db.h"

namespace lego {

namespace block {

AccountManager* AccountManager::Instance() {
    static AccountManager ins;
    return &ins;
}

AccountManager::AccountManager() {
    network_block_ = new TxBlockInfoPtr[common::kImmutablePoolSize];
    std::fill(network_block_, network_block_ + common::kImmutablePoolSize, nullptr);
}

AccountManager::~AccountManager() {
    if (network_block_ != nullptr) {
        delete []network_block_;
    }
}

AccountInfoPtr AccountManager::GetAcountInfo(const std::string& acc_id) {
    std::lock_guard<std::mutex> guard(acc_map_mutex_);
    auto iter = acc_map_.find(acc_id);
    if (iter != acc_map_.end()) {
        return iter->second;
    }
    return nullptr;
}

int AccountManager::AddBlockItem(const bft::protobuf::Block& block_item) {
    const auto& tx_list = block_item.tx_block().tx_list();
    if (tx_list.empty()) {
        BLOCK_ERROR("tx block tx list is empty.");
        return kBlockError;
    }
    
    statis::Statistics::Instance()->inc_tx_count(tx_list.size());
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].to_add()) {
            statis::Statistics::Instance()->inc_tx_amount(tx_list[i].amount());
            if (CheckNetworkIdValid(tx_list[i].to()) != kBlockSuccess) {
                continue;
            }
            auto acc_ptr = std::make_shared<AccountInfo>(
                    tx_list[i].to(),
                    tx_list[i].balance(),
                    block_item.height());
            ++(acc_ptr->in_count);
            acc_ptr->in_lego = tx_list[i].amount();
            AddAccount(acc_ptr);
            uint32_t pool_idx = common::GetPoolIndex(tx_list[i].to());
            auto bptr = std::make_shared<TxBlockInfo>(
                    block_item.hash(),
                    block_item.height(),
                    block_item.tx_block().network_id(),
                    block_item.tx_block().network_id(),
                    pool_idx);
            SetPool(bptr);
            std::string tx_gid = common::GetTxDbKey(false, tx_list[i].gid());
            db::Db::Instance()->Put(tx_gid, block_item.hash());

            // just call smart contract but these attr is not 'to' signed, don't add to 'to'
            std::map<std::string, std::string> attr_map;
            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                // every attr just check last block
                attr_map[tx_list[i].attr(attr_idx).key()] = tx_list[i].attr(attr_idx).value();
            }

            if (!tx_list[i].smart_contract_addr().empty()) {
                contract::ContractManager::Instance()->InitWithAttr(
                        block_item.height(),
                        tx_list[i]);
            }
        } else {
            if (CheckNetworkIdValid(tx_list[i].from()) != kBlockSuccess) {
                continue;
            }
            auto acc_ptr = std::make_shared<AccountInfo>(
                    tx_list[i].from(),
                    tx_list[i].balance(),
                    block_item.height());
            if (!tx_list[i].to().empty()) {
                ++(acc_ptr->out_count);
                acc_ptr->out_lego = tx_list[i].amount();
            } else {
                acc_ptr->new_height = block_item.height();
            }

            // now just sender can modify attrs
            std::map<std::string, std::string> attr_map;
            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                // every attr just check last block
                attr_map[tx_list[i].attr(attr_idx).key()] = tx_list[i].attr(attr_idx).value();
                std::lock_guard<std::mutex> acc_guard(acc_ptr->attrs_with_height_mutex);
                acc_ptr->attrs_with_height[tx_list[i].attr(attr_idx).key()] = block_item.height();
            }

            if (!tx_list[i].smart_contract_addr().empty()) {
                contract::ContractManager::Instance()->InitWithAttr(
                        block_item.height(),
                        tx_list[i]);
            }
            AddAccount(acc_ptr);

            uint32_t pool_idx = common::GetPoolIndex(tx_list[i].from());
            auto bptr = std::make_shared<TxBlockInfo>(
                    block_item.hash(),
                    block_item.height(),
                    block_item.tx_block().network_id(),
                    block_item.tx_block().network_id(),
                    pool_idx);
            SetPool(bptr);
            std::string tx_gid = common::GetTxDbKey(true, tx_list[i].gid());
            db::Db::Instance()->Put(tx_gid, block_item.hash());
        }
    }
    return kBlockSuccess;
}

void AccountManager::AddAccount(const AccountInfoPtr& acc_ptr) {
    std::lock_guard<std::mutex> guard(acc_map_mutex_);
    auto iter = acc_map_.find(acc_ptr->account_id);
    if (iter == acc_map_.end()) {
        acc_map_[acc_ptr->account_id] = acc_ptr;
        if (acc_ptr->in_lego > 0 || acc_ptr->out_lego > 0) {
            acc_map_[acc_ptr->account_id]->AddHeight(acc_ptr->height);
        }
        return;
    }

    if (iter->second->height <= acc_ptr->height) {
        acc_ptr->in_count += iter->second->in_count;
        acc_ptr->out_count += iter->second->out_count;
        acc_ptr->in_lego += iter->second->in_lego;
        acc_ptr->out_lego += iter->second->out_lego;
        acc_ptr->height_pri_queue = acc_map_[acc_ptr->account_id]->get_height_pri_queue();
        std::lock_guard<std::mutex> tmp_guard(acc_map_[acc_ptr->account_id]->attrs_with_height_mutex);
        for (auto sub_iter = acc_map_[acc_ptr->account_id]->attrs_with_height.begin();
                sub_iter != acc_map_[acc_ptr->account_id]->attrs_with_height.end(); ++sub_iter) {
            auto e_iter = acc_ptr->attrs_with_height.find(sub_iter->first);
            if (e_iter == acc_ptr->attrs_with_height.end()) {
                acc_ptr->attrs_with_height[sub_iter->first] = sub_iter->second;
            }
        }
        acc_map_[acc_ptr->account_id] = acc_ptr;
    } else {
        acc_map_[acc_ptr->account_id]->in_count += acc_ptr->in_count;
        acc_map_[acc_ptr->account_id]->out_count += acc_ptr->out_count;
        acc_map_[acc_ptr->account_id]->in_lego += acc_ptr->in_lego;
        acc_map_[acc_ptr->account_id]->out_lego += acc_ptr->out_lego;
        acc_map_[acc_ptr->account_id]->new_height = acc_ptr->new_height;
        std::lock_guard<std::mutex> tmp_guard(acc_map_[acc_ptr->account_id]->attrs_with_height_mutex);
        for (auto sub_iter = acc_ptr->attrs_with_height.begin();
                sub_iter != acc_ptr->attrs_with_height.end(); ++sub_iter) {
            auto e_iter = acc_map_[acc_ptr->account_id]->attrs_with_height.find(sub_iter->first);
            if (e_iter == acc_map_[acc_ptr->account_id]->attrs_with_height.end()) {
                acc_map_[acc_ptr->account_id]->attrs_with_height[sub_iter->first] = sub_iter->second;
            }
        }
    }

    if (acc_ptr->in_lego > 0 || acc_ptr->out_lego > 0) {
        acc_map_[acc_ptr->account_id]->AddHeight(acc_ptr->height);
    }
}

TxBlockInfoPtr AccountManager::GetBlockInfo(uint32_t pool_idx) {
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    return network_block_[pool_idx];
}

void AccountManager::SetPool(const TxBlockInfoPtr& block_ptr) {
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    if (network_block_[block_ptr->pool_index] != nullptr) {
        if (network_block_[block_ptr->pool_index]->height >= block_ptr->height) {
            return;
        }
    }
    network_block_[block_ptr->pool_index] = block_ptr;
    std::string key = GetLastBlockHash(common::kTestForNetworkId, block_ptr->pool_index);
    db::Db::Instance()->Put(key, block_ptr->hash);
}

int AccountManager::CheckNetworkIdValid(const std::string& acc_addr) {
    return kBlockSuccess;
}

}  // namespace block

}  //namespace lego
