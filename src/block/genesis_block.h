#pragma once

#include "block/block_utils.h"

namespace lego {

namespace block {

class GenesisBlock {
public:
    static int WriteGenesisBlock(uint32_t pool_idx, std::string& sha256);

private:
    GenesisBlock();
    ~GenesisBlock();
    DISALLOW_COPY_AND_ASSIGN(GenesisBlock);
};

}  // namespace block

}  // namespace lego
