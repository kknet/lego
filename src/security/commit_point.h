#pragma once

#include <memory>

#include <openssl/ec.h>
#include "security/commit_secret.h"

namespace lego {

namespace security {

class CommitPoint {
public:
    CommitPoint();
    explicit CommitPoint(CommitSecret& secret);
    explicit CommitPoint(const std::string& src);
    CommitPoint(const CommitPoint&);
    ~CommitPoint();
    void Set(CommitSecret& secret);
    CommitPoint& operator=(const CommitPoint& src);
    bool operator==(const CommitPoint& r) const;
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);

    bool inited() const {
        return inited_;
    }
    const std::shared_ptr<EC_POINT>& ec_point() const {
        return ec_point_;
    }

private:
    std::shared_ptr<EC_POINT> ec_point_;
    bool inited_{ false };

};

}  // namespace security

}  // namespace lego
