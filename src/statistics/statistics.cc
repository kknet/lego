#include "statistics/statistics.h"

#include "block/account_manager.h"

namespace lego {

namespace statis {

Statistics* Statistics::Instance() {
    static Statistics ins;
    return &ins;
}

Statistics::Statistics() {
    statis_tick_.CutOff(kTpsUpdatePeriod, std::bind(&Statistics::StatisUpdate, this));
    period_begin_ = std::chrono::steady_clock::now();
    uint64_t amount = 100000;
    uint32_t addr_count = 0;
    for (uint32_t i = 0; i < kMaxQueueSize; ++i) {
        auto rand_num = std::rand() % 10000;
        tps_queue_.push_back((float)rand_num * 10.0 / 10000.0);
        addr_count += std::rand() % 2;
        addr_q_.push_back(addr_count);
        tx_count_q_.push_back(std::rand() % 3000);
        amount += std::rand() % 2000;
        tx_amount_q_.push_back(amount);
    }
}

Statistics::~Statistics() {}

void Statistics::StatisUpdate() {
    addr_count_ = block::AccountManager::Instance()->addr_count();
    std::lock_guard<std::mutex> gaurd(change_mutex_);
    float tps = (float)period_tx_count_ / 10.0;
    tps_queue_.push_back(tps);
    if (tps_queue_.size() > kMaxQueueSize) {
        tps_queue_.pop_front();
    }

    auto tick_now = std::chrono::steady_clock::now();
    auto period_tick = period_begin_ + std::chrono::minutes(60);
    if (tick_now >= period_tick) {
        addr_q_.push_back(addr_count_);
        period_begin_ = tick_now;
        tx_count_q_.push_back(tx_count_);
        tx_count_ = 0;
        tx_amount_q_.push_back(tx_amount_);
        tx_amount_ = 0;
        if (tx_count_q_.size() > kMaxQueueSize) {
            tx_count_q_.pop_front();
        }

        if (tx_amount_q_.size() > kMaxQueueSize) {
            tx_amount_q_.pop_front();
        }

        if (addr_q_.size() > kMaxQueueSize) {
            addr_q_.pop_front();
        }
    }
    statis_tick_.CutOff(kTpsUpdatePeriod, std::bind(&Statistics::StatisUpdate, this));
}

}  // namespace statis

}  // namespace lego