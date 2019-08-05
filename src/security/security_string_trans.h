#pragma once

#include <mutex>
#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "common/utils.h"

namespace lego {

namespace security {

class SecurityStringTrans {
public:
    static SecurityStringTrans* Instance();

    std::shared_ptr<BIGNUM> StringToBignum(const std::string& src);
    void BignumToString(
            const std::shared_ptr<BIGNUM>& value,
            std::string& dst);
    std::shared_ptr<EC_POINT> StringToEcPoint(const std::string& src);
    void EcPointToString(
        const std::shared_ptr<EC_POINT>& value,
            std::string& dst);

private:
    SecurityStringTrans() {}
    ~SecurityStringTrans() {}

    std::mutex bitnum_mutex_;
    std::mutex ecpoint_mutex_;

    DISALLOW_COPY_AND_ASSIGN(SecurityStringTrans);
};

}  // namespace security

}  // namespace lego
