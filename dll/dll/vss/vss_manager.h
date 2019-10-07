#pragma once

#include "common/utils.h"

namespace lego {

namespace vss {

class VssManager {
public:
    static VssManager* Instance();
    uint32_t EpochRandom() {
        return epoch_random_;
    }

private:
    VssManager() {}
    ~VssManager() {}

    uint32_t epoch_random_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(VssManager);
};

}  // namespace vss

}  // namespace lego
