#pragma once

#include <chrono>

#include "limit/limit_interface.h"

namespace lego {

namespace limit {

class TockenBucket : public LimitInterface {
public:
    TockenBucket(int32_t max_tockens)
            : up_tockens_(max_tockens),
              down_tockens_(max_tockens),
              max_tockens_(max_tockens),
              tockens_add_per_ms_(static_cast<float>(max_tockens_) / 1000.0f) {
        pre_up_timestamp_ = std::chrono::system_clock::now();
        pre_down_timestamp_ = std::chrono::system_clock::now();
    }
    virtual ~TockenBucket() {}
    virtual bool UpCheckLimit(uint32_t stream);
    virtual bool DownCheckLimit(uint32_t stream);

private:
    static const uint32_t kIncreaseTockenPeriod = 10u;

    std::chrono::system_clock::time_point pre_up_timestamp_;
    std::chrono::system_clock::time_point pre_down_timestamp_;
    int32_t up_tockens_;
    int32_t down_tockens_;
    int32_t max_tockens_;
    float tockens_add_per_ms_;
    bool download_valid_{ true };

    DISALLOW_COPY_AND_ASSIGN(TockenBucket);
};

}  // namespace limit

}  // namespace lego
