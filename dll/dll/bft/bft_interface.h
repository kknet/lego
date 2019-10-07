#pragma once

#include <memory>
#include <string>
#include <mutex>
#include <unordered_map>

#include "common/utils.h"
#include "common/bitmap.h"
#include "security/signature.h"
#include "security/commit_secret.h"
#include "security/schnorr.h"
#include "security/commit_point.h"
#include "security/challenge.h"
#include "security/multi_sign.h"
#include "security/response.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/member_manager.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace bft {

struct BackupResponse {
    uint32_t index;
    security::Response response;
    security::CommitSecret secret;
};
typedef std::shared_ptr<BackupResponse> BackupResponsePtr;

class BftInterface {
public:
    virtual int Init(bool leader) = 0;
    virtual std::string name() = 0;
    virtual int Prepare(bool leader, std::string& prepare) = 0;
    virtual int PreCommit(bool leader, std::string& pre_commit) = 0;
    virtual int Commit(bool leader, std::string& commit) = 0;

public:
    bool CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg);
    int LeaderPrecommitOk(uint32_t index, bool agree, const security::CommitSecret& secret);
    int LeaderCommitOk(uint32_t index, bool agree, const security::Response& res);
    int BackupCheckAggSign(const bft::protobuf::BftMessage& bft_msg);

    void set_pool_index(uint32_t pool_idx) {
        pool_index_ = pool_idx;
    }

    uint32_t pool_index() {
        return pool_index_;
    }

    void set_gid(const std::string& gid) {
        gid_ = gid;
    }

    const std::string& gid() {
        return gid_;
    }

    void set_network_id(uint32_t net_id) {
        network_id_ = net_id;
    }

    uint32_t network_id() {
        return network_id_;
    }

    void set_randm_num(uint64_t rnum) {
        rand_num_ = rnum;
    }

    uint64_t rand_num() {
        return rand_num_;
    }

    void set_member_count(uint32_t mem_cnt) {
        member_count_ = mem_cnt;
        min_aggree_member_count_ = static_cast<uint32_t>(
                (2.0 / 3.0) * (float)member_count_ + 0.5f);
        min_oppose_member_count_ = static_cast<uint32_t>(
                (1.0 / 3.0) * (float)member_count_ + 0.5f);
        min_prepare_member_count_ = static_cast<uint32_t>(
                (9.5 / 10.0) * (float)member_count_ + 0.5f);
    }

    const common::Bitmap& precommit_bitmap() const {
        return precommit_bitmap_;
    }

    void set_status(uint32_t status) {
        status_ = status;
    }

    uint32_t status() {
        return status_;
    }

    std::vector<uint64_t> item_index_vec() {
        std::lock_guard<std::mutex> guard(item_index_vec_mutex_);
        return item_index_vec_;
    }

    void add_item_index_vec(uint64_t index) {
        std::lock_guard<std::mutex> guard(item_index_vec_mutex_);
        item_index_vec_.push_back(index);
    }

    void reset_timeout() {
        timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftTimeout));
    }

    bool timeout() {
        return (timeout_ <= std::chrono::steady_clock::now());
    }

    uint32_t leader_precommit_agree() {
        return leader_precommit_agree_;
    }

    uint32_t leader_commit_agree() {
        return leader_commit_agree_;
    }

    uint32_t member_count() {
        return member_count_;
    }

    uint32_t min_agree_member_count() {
        return min_aggree_member_count_;
    }

    void set_mem_manager(std::shared_ptr<MemberManager>& mem_manager) {
        mem_manager_ = mem_manager;
    }

    const std::string& prepare_hash() const {
        return prepare_hash_;
    }

    void set_prepare_hash(const std::string& prepare_hash) {
        prepare_hash_ = prepare_hash;
    }

    uint32_t leader_index() const {
        return leader_index_;
    }

    void set_challenge(const security::Challenge& challenge) {
        challenge_ = challenge;
    }

    const security::Challenge& challenge() const {
        assert(challenge_.inited());
        return challenge_;
    }

    const security::CommitSecret& secret() const {
        assert(secret_.inited());
        return secret_;
    }

    const std::shared_ptr<security::Signature>& agg_sign() const {
        assert(agg_sign_ != nullptr);
        return agg_sign_;
    }

    void init_prepare_timeout() {
        prepare_timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftLeaderPrepareWaitPeriod));
    }

    void init_precommit_timeout() {
        precommit_timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftLeaderPrepareWaitPeriod));
    }

    std::vector<std::string> bft_item_vec() {
        std::lock_guard<std::mutex> guard(bft_item_vec_mutex_);
        return bft_item_vec_;
    }

    void push_bft_item_vec(const std::string& gid) {
        std::lock_guard<std::mutex> guard(bft_item_vec_mutex_);
        bft_item_vec_.push_back(gid);
    }

    uint32_t bft_item_count() {
        return bft_item_vec_.size();
    }

    const std::shared_ptr<bft::protobuf::Block>& prpare_block() const {
        return prpare_block_;
    }

protected:
    BftInterface() {
        bft_item_vec_.reserve(kBftOneConsensusMaxCount);
        reset_timeout();
    }
    virtual ~BftInterface() {}
    void SetBlock(std::shared_ptr<bft::protobuf::Block>& prpare_block) {
        prpare_block_ = prpare_block;
    }

private:
    int LeaderCreatePreCommitAggChallenge();
    int LeaderCreateCommitAggSign();

    uint32_t pool_index_{ std::numeric_limits<uint32_t>::max() };
    std::string gid_;
    uint32_t network_id_{ 0 };
    uint32_t leader_index_{ 0 };
    uint64_t rand_num_{ 0 };
    uint32_t leader_precommit_agree_{ 0 };
    uint32_t leader_commit_agree_{ 0 };
    uint32_t leader_precommit_oppose_{ 0 };
    uint32_t leader_commit_oppose_{ 0 };
    bool leader_handled_precommit_{ false };
    bool leader_handled_commit_{ false };
    std::mutex mutex_;
    uint32_t member_count_{ 0 };
    uint32_t min_aggree_member_count_{ 0 };
    uint32_t min_oppose_member_count_{ 0 };
    uint32_t min_prepare_member_count_{ 0 };
    common::Bitmap prepare_bitmap_{ kBftLeaderBitmapSize };
    common::Bitmap precommit_bitmap_{ kBftLeaderBitmapSize };
    uint32_t status_{ kBftInit };
    std::vector<uint64_t> item_index_vec_;
    std::mutex item_index_vec_mutex_;
    std::chrono::steady_clock::time_point timeout_;
    std::shared_ptr<MemberManager> mem_manager_{ nullptr };
    std::string prepare_hash_;
    std::unordered_map<uint32_t, BackupResponsePtr> backup_prepare_response_;
    std::unordered_map<uint32_t, BackupResponsePtr> backup_precommit_response_;
    security::Challenge challenge_;
    security::CommitSecret secret_;
    std::shared_ptr<security::Signature> agg_sign_{ nullptr };
    std::chrono::steady_clock::time_point prepare_timeout_;
    std::chrono::steady_clock::time_point precommit_timeout_;
    std::vector<std::string> bft_item_vec_;
    std::mutex bft_item_vec_mutex_;
    std::shared_ptr<bft::protobuf::Block> prpare_block_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(BftInterface);
};

typedef std::shared_ptr<BftInterface> BftInterfacePtr;

}  // namespace bft

}  // namespace lego
