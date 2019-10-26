#include "limit/tocken_bucket.h"

#include "common/time_utils.h"

namespace lego {

namespace limit {

bool TockenBucket::UpCheckLimit(uint32_t stream) {
    auto period_ms = common::TimeUtils::PeriodMs(pre_timestamp_);
    if (period_ms >= kIncreaseTockenPeriod) {
        up_tockens_ += static_cast<int32_t>(period_ms * tockens_add_per_ms_);
        if (up_tockens_ > max_tockens_) {
            up_tockens_ = max_tockens_;
        }
        pre_timestamp_ = std::chrono::steady_clock::now() + std::chrono::microseconds(0);
    }

    if (down_tockens_ <= 0) {
        return false;
    }

    if (up_tockens_ < stream) {
        up_tockens_ = 0;
        return false;
    }

    up_tockens_ -= stream;
    return true;
}

bool TockenBucket::DownCheckLimit(uint32_t stream) {
    auto period_ms = common::TimeUtils::PeriodMs(pre_timestamp_);
    if (period_ms >= kIncreaseTockenPeriod) {
        down_tockens_ += static_cast<uint32_t>(period_ms * tockens_add_per_ms_);
        if (down_tockens_ > max_tockens_) {
            down_tockens_ = max_tockens_;
        }
    }

    if (down_tockens_ < stream) {
        down_tockens_ = 0;
        return false;
    }

    down_tockens_ -= stream;
    return true;
}


}  // namespace limit

}  // namespace lego
