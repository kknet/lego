#include "bft/bft_interface.h"

#include "common/encode.h"
#include "common/global_info.h"
#include "vss/vss_manager.h"

namespace lego {

namespace bft {

bool BftInterface::CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!bft_msg.has_node_id()) {
        BFT_ERROR("bft message has no node_id.");
        return false;
    }

    if (!bft_msg.has_net_id()) {
        BFT_ERROR("bft message has no net id.");
        return false;
    }

    if (!mem_manager_->IsLeader(
            bft_msg.net_id(),
            bft_msg.node_id(),
            vss::VssManager::Instance()->EpochRandom())) {
        auto member_ptr = mem_manager_->GetNetworkMembers(bft_msg.net_id());
        auto mem_ptr = (*member_ptr)[0];
        BFT_ERROR("is not leader: %s, %s",
            common::Encode::HexEncode(bft_msg.node_id()).c_str(),
            common::Encode::HexEncode(mem_ptr->id).c_str());
        for (auto iter = member_ptr->begin(); iter != member_ptr->end(); ++iter) {
            BFT_ERROR("%s", common::Encode::HexEncode((*iter)->id).c_str());
        }

        BFT_ERROR("prepare message not leader.[%u][%s][%u]",
                bft_msg.net_id(),
                common::Encode::HexEncode(bft_msg.node_id()).c_str(),
                vss::VssManager::Instance()->EpochRandom());
        return false;
    }

    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("bft message has no sign challenge or sign response.");
        return false;
    }

    auto leader_mem_ptr = mem_manager_->GetMember(bft_msg.net_id(), bft_msg.node_id());
    if (leader_mem_ptr == nullptr) {
        BFT_ERROR("get leader bft member failed!");
        return false;
    }
    set_prepare_hash(common::Hash::Hash128(bft_msg.data()));
    security::Signature sign(bft_msg.sign_challenge(), bft_msg.sign_response());
    if (!security::Schnorr::Instance()->Verify(prepare_hash(), sign, leader_mem_ptr->pubkey)) {
        BFT_ERROR("leader signature verify failed!");
        return false;
    }

    auto local_mem_ptr = mem_manager_->GetMember(
            bft_msg.net_id(),
            common::GlobalInfo::Instance()->id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    leader_index_ = leader_mem_ptr->index;
    secret_ = local_mem_ptr->secret;
    return true;
}

int BftInterface::LeaderPrecommitOk(
        uint32_t index,
        bool agree,
        const security::CommitSecret& secret) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_precommit_) {
        return kBftHandled;
    }

    if (agree) {
        ++leader_precommit_agree_;
        auto backup_res = std::make_shared<BackupResponse>();
        backup_res->index = index;
        backup_res->secret = secret;
        auto iter = backup_prepare_response_.insert(std::make_pair(index, backup_res));
        assert(iter.second);
        prepare_bitmap_.Set(index);
    } else {
        ++leader_precommit_oppose_;
    }

    auto now_timestamp = std::chrono::steady_clock::now();
    if (leader_precommit_agree_ >= min_prepare_member_count_ ||
            (leader_precommit_agree_ > min_aggree_member_count_ &&
            now_timestamp >= prepare_timeout_)) {
        LeaderCreatePreCommitAggChallenge();
        leader_handled_precommit_ = true;
        return kBftAgree;
    }

    if (leader_precommit_oppose_ >= min_oppose_member_count_) {
        leader_handled_precommit_ = true;
        return kBftOppose;
    }
    return kBftWaitingBackup;
}

int BftInterface::LeaderCommitOk(uint32_t index, bool agree, const security::Response& res) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_commit_) {
        return kBftHandled;
    }

    if (agree) {
        ++leader_commit_agree_;
        precommit_bitmap_.Set(index);
        auto backup_res = std::make_shared<BackupResponse>();
        backup_res->response = res;
        backup_res->index = index;
        backup_precommit_response_[index] = backup_res;  // just cover with rechallenge
    } else {
        ++leader_commit_oppose_;
    }

    if (precommit_bitmap_ == prepare_bitmap_) {
        leader_handled_commit_ = true;
        if (LeaderCreateCommitAggSign() != kBftSuccess) {
            BFT_ERROR("leader create commit agg sign failed!");
            return kBftOppose;
        }
        return kBftAgree;
    }

    auto now_timestamp = std::chrono::steady_clock::now();
    if (now_timestamp >= precommit_timeout_) {
        // todo re-challenge
        if (precommit_bitmap_.valid_count() < min_aggree_member_count_) {
            BFT_ERROR("precommit_bitmap_.valid_count() failed!");
            return kBftOppose;
        }
        prepare_bitmap_ = precommit_bitmap_;
        LeaderCreatePreCommitAggChallenge();
        return kBftReChallenge;
    }

    if (leader_commit_oppose_ >= min_oppose_member_count_) {
        leader_handled_commit_ = true;
        BFT_ERROR("oppose count limited!");
        return kBftOppose;
    }
    return kBftWaitingBackup;
}

int BftInterface::LeaderCreatePreCommitAggChallenge() {
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = prepare_bitmap_.data().size() * 64;
    std::vector<security::CommitPoint> points;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!prepare_bitmap_.Valid(i)) {
            continue;
        }

        auto mem_ptr = mem_manager_->GetMember(network_id(), i);
        pubkeys.push_back(mem_ptr->pubkey);
        auto iter = backup_prepare_response_.find(i);
        assert(iter != backup_prepare_response_.end());
        points.push_back(security::CommitPoint(iter->second->secret));
    }

    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    auto agg_commit = security::MultiSign::AggregateCommits(points);
    assert(agg_commit != nullptr);
    challenge_ = security::Challenge(*agg_commit, *agg_pubkey, prepare_hash());
    assert(challenge_.inited());
    return kBftSuccess;
}

int BftInterface::LeaderCreateCommitAggSign() {
    assert(precommit_bitmap_ == prepare_bitmap_);
    std::vector<security::Response> responses;
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = precommit_bitmap_.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!precommit_bitmap_.Valid(i)) {
            continue;
        }

        auto mem_ptr = mem_manager_->GetMember(network_id(), i);
        auto iter = backup_precommit_response_.find(i);
        assert(iter != backup_precommit_response_.end());
        responses.push_back(iter->second->response);
        pubkeys.push_back(mem_ptr->pubkey);
    }

    auto agg_response = security::MultiSign::AggregateResponses(responses);
    assert(agg_response != nullptr);
    agg_sign_ = security::MultiSign::AggregateSign(challenge_, *agg_response);
    assert(agg_sign_ != nullptr);
    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    if (!security::MultiSign::Instance()->MultiSigVerify(
            prepare_hash(),
            *agg_sign_,
            *agg_pubkey)) {
        BFT_ERROR("leader agg sign and check it failed!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftInterface::BackupCheckAggSign(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!bft_msg.has_agg_sign_challenge() ||
            !bft_msg.has_agg_sign_response() ||
            bft_msg.bitmap_size() <= 0) {
        BFT_ERROR("commit must have agg sign.");
        return kBftError;
    }
    auto sign = security::Signature(
            bft_msg.agg_sign_challenge(),
            bft_msg.agg_sign_response());

    std::vector<uint64_t> data;
    for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
        data.push_back(bft_msg.bitmap(i));
    }

    common::Bitmap leader_agg_bitmap(data);
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = leader_agg_bitmap.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!leader_agg_bitmap.Valid(i)) {
            continue;
        }

        auto mem_ptr = mem_manager_->GetMember(network_id(), i);
        pubkeys.push_back(mem_ptr->pubkey);
    }

    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    if (!security::MultiSign::Instance()->MultiSigVerify(
            prepare_hash(),
            sign,
            *agg_pubkey)) {
        return kBftError;
    }
    return kBftSuccess;
}

}  // namespace bft

}  // namespace lego
