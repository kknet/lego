#pragma once

#include <memory>

#include <openssl/bn.h>
#include "security/commit_point.h"

namespace lego {

namespace security {

class CommitPointHash {
public:
    CommitPointHash();
    CommitPointHash(const CommitPoint& point);
    CommitPointHash(const std::string& src);
    CommitPointHash(const CommitPointHash& src);
    ~CommitPointHash();
    void Set(const CommitPoint& point);
    CommitPointHash& operator=(const CommitPointHash& src);
    bool operator==(const CommitPointHash& r) const;
    int Deserialize(const std::string& src);
    uint32_t Serialize(std::string& dst) const;

private:
    std::shared_ptr<BIGNUM> bignum_;
    bool inited_{ false };
};

}  // namespace security

}  // namespace lego
