#include "stdafx.h"
#include "common/tick.h"

#include <cassert>

#include "common/global_info.h"

namespace lego {

namespace common {

Tick::Tick() : tick_index_(TickThreadPool::Instance()->TickIndex()) {}

Tick::~Tick() {
    Destroy();
}

void Tick::CutOff(int64_t cutoff_us, TickCallbackFunction call) {
    TickThreadPool::Instance()->AddTick(tick_index_, cutoff_us, call);
}

void Tick::Destroy() {
    TickThreadPool::Instance()->RemoveTick(tick_index_);
}

IndependentTick::IndependentTick()
        : tick_list_(),
          timer_list_mutex_(),
          timer_thread_(nullptr),
          destroy_(false) {
    timer_thread_.reset(new std::thread(&IndependentTick::TimerFlies, this));
}

IndependentTick::~IndependentTick() {
    Destroy();
}

void IndependentTick::Destroy() {
    destroy_ = true;
    if (timer_thread_) {
        timer_thread_->join();
        timer_thread_ = nullptr;
    }

    {
        std::unique_lock<std::mutex> lock(timer_list_mutex_);
        tick_list_.clear();
    }
}

void IndependentTick::CutOff(int64_t wait_us, TickCallbackFunction func) {
    std::unique_lock<std::mutex> lock(timer_list_mutex_);
    auto tp_timeout = std::chrono::steady_clock::now() + std::chrono::microseconds(wait_us);
    tick_list_.push_back(std::make_pair(tp_timeout, func));
}

void IndependentTick::TimerFlies() {
    while (!common::global_stop) {
        std::vector<TickCallbackFunction> func_vec;
        {
            std::unique_lock<std::mutex> lock(timer_list_mutex_);
            auto tp_now = std::chrono::steady_clock::now();
            auto iter = tick_list_.begin();
            while (iter != tick_list_.end()) {
                if (iter->first <= tp_now) {
                    func_vec.push_back(iter->second);
                    iter = tick_list_.erase(iter);
                } else {
                    ++iter;
                }
            }
        }

        for (auto iter = func_vec.begin(); iter != func_vec.end(); ++iter) {
            (*iter)();
        }
        std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
    }
}
}  // namespace common

}  // namespace lego
