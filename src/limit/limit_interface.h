#pragma once

#include <chrono>

#include "limit/limit_utils.h"

namespace lego {

namespace limit {

class LimitInterface {
public:
    virtual bool UpCheckLimit(uint32_t stream) = 0;
    virtual bool DownCheckLimit(uint32_t stream) = 0;

protected:
    LimitInterface() {}
    virtual ~LimitInterface() {}

private:

    DISALLOW_COPY_AND_ASSIGN(LimitInterface);
};

}  // namespace limit

}  // namespace lego
