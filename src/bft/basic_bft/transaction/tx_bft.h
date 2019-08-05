#pragma once

#include <string>

#include "bft/bft_interface.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "bft/basic_bft/transaction/proto/tx_proto.h"

namespace lego {

namespace bft {

class TxBft : public BftInterface {
public:
    TxBft();
    virtual ~TxBft();
    virtual int Init(bool leader);
    virtual std::string name() {
        return kTransactionPbftAddress;
    }
    virtual int Prepare(bool leader, std::string& prepare);
    virtual int PreCommit(bool leader, std::string& pre_commit);
    virtual int Commit(bool leader, std::string& commit);

private:
    int LeaderCreatePrepare(std::string& bft_str);
    int BackupCheckPrepare(std::string& bft_str);
    int LeaderCreatePreCommit(std::string& bft_str);
    int LeaderCreateCommit(std::string& bft_str);
    int CheckBlockInfo(const protobuf::Block& block_info);
    int CheckTxInfo(const protobuf::Block& block_info, const protobuf::TxInfo& tx_info);

    DISALLOW_COPY_AND_ASSIGN(TxBft);
};

}  // namespace bft

}  //namespace lego
