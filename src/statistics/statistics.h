#pragma once

#include <atomic>
#include <deque>
#include <queue>

#include "httplib.h"
#include "common/tick.h"
#include "block/block_utils.h"
#include "statistics/statis_utils.h"

namespace lego {

namespace statis {

class Statistics {
public:
    static Statistics* Instance();

    void inc_tx_count(uint32_t count) {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        tx_count_ += count;
        all_tx_count_ += count;
    }

    uint32_t tx_count() {
        return tx_count_;
    }

    uint32_t all_tx_count() {
        return all_tx_count_;
    }

    void inc_tx_amount(uint64_t amount) {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        tx_amount_ += amount;
        all_tx_amount_ += amount;
    }

    uint64_t tx_amount() {
        return tx_amount_;
    }

    uint64_t all_tx_amount() {
        return all_tx_amount_;
    }

    float tps() {
        return tps_;
    }

    void inc_period_tx_count(uint32_t count) {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        period_tx_count_ += count;
    }

    std::deque<float> tps_queue() {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        return tps_queue_;
    }

    std::deque<uint32_t> tx_count_q() {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        return tx_count_q_;
    }

    std::deque<uint64_t> tx_amount_q() {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        return tx_amount_q_;
    }

    std::deque<uint32_t> addr_q() {
        std::lock_guard<std::mutex> gaurd(change_mutex_);
        return addr_q_;
    }

    uint32_t addr_count() {
        return addr_count_;
    }

    void AddNewAccount(const block::AccountInfoPtr& acc_ptr);
    void GetBestAddr(nlohmann::json& res_json);

private:
    struct AccountOperator {
        bool operator() (const block::AccountInfoPtr& lhs, const block::AccountInfoPtr& rhs) {
            return lhs->balance > rhs->balance;
        }
    };
    typedef std::priority_queue<block::AccountInfoPtr,
            std::vector<block::AccountInfoPtr>,
            AccountOperator> PriQueue;

    Statistics();
    ~Statistics();
    void StatisUpdate();

    static const uint32_t kTpsUpdatePeriod = 10u * 1000u * 1000u;
    static const uint32_t kMaxQueueSize = 128u;
    static const uint32_t kQueuePeriod = 60u;  // 60 min
    static const uint32_t kMaxBestAcountCount = 50u;

    uint32_t tx_count_{ 0 };
    uint64_t tx_amount_{ 0 };
    uint32_t all_tx_count_{ 0 };
    uint64_t all_tx_amount_{ 0 };
    uint32_t period_tx_count_{ 0 };
    float tps_{ 0.0f };
    common::Tick statis_tick_;
    std::deque<float> tps_queue_;
    std::deque<uint32_t> tx_count_q_;
    std::deque<uint64_t> tx_amount_q_;
    std::chrono::steady_clock::time_point period_begin_;
    std::mutex change_mutex_;
    uint32_t addr_count_{ 0 };
    std::deque<uint32_t> addr_q_;
    PriQueue acc_pri_q_;
    std::mutex acc_pri_q_mutex_;
    uint64_t all_acc_lego_{ 0 };
    std::shared_ptr<std::unordered_map<std::string, block::AccountInfoPtr>> acc_addr_ptr_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(Statistics);
};

}  // namespace statis

}  // namespace lego
