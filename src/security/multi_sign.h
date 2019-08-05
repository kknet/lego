#pragma once

#include <mutex>
#include <vector>

#include "common/utils.h"
#include "security/public_key.h"
#include "security/signature.h"
#include "security/challenge.h"
#include "security/response.h"

namespace lego {

namespace security {

class MultiSign {
public:
    static MultiSign* Instance();
    static std::shared_ptr<PublicKey> AggregatePubKeys(
            const std::vector<PublicKey>& pubkeys);
    static std::shared_ptr<CommitPoint> AggregateCommits(
            const std::vector<CommitPoint>& commit_points);
    static std::shared_ptr<Response> AggregateResponses(
            const std::vector<Response>& responses);
    static std::shared_ptr<Signature> AggregateSign(
            const Challenge& challenge,
            const Response& agg_response);
    static bool VerifyResponse(
            const Response& response,
            const Challenge& challenge,
            const PublicKey& pubkey,
            const CommitPoint& commit_point);
    bool MultiSigVerify(
            const std::string& message,
            const Signature& toverify,
            const PublicKey& pubkey);
    static bool SignKey(
            const std::string& message_with_pubkey,
            const PublicKey& pub_key,
            const PrivateKey& pri_key,
            Signature& signature);
    static bool VerifyKey(
            const std::string& message_with_pubkey,
            const Signature& signature,
            const PublicKey& pub_key);
private:
    MultiSign() {}
    ~MultiSign() {}

    std::mutex multi_sign_mutex_;
    DISALLOW_COPY_AND_ASSIGN(MultiSign);
};

}  // namespace security

}  // namespace lego
