#include "stdafx.h"
#include "vss/vss_manager.h"

namespace lego {

namespace vss {

VssManager* VssManager::Instance() {
    static VssManager ins;
    return &ins;
}

}  // namespace vss

}  // namespace lego
