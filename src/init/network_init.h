#pragma once

#include "common/utils.h"
#include "common/config.h"
#include "common/parse_args.h"
#include "common/tick.h"
#include "transport/transport.h"
#include "election/elect_manager.h"
#include "init/command.h"

namespace lego {

namespace init {

class NetworkInit {
public:
    NetworkInit();
    ~NetworkInit();
    int Init(int argc, char** argv);

private:
    int InitConfigWithArgs(int argc, char** argv);
    int InitTransport();
    int ParseParams(int argc, char** argv, common::ParserArgs& parser_arg);
    int ResetConfig(common::ParserArgs& parser_arg);
    int InitNetworkSingleton();
    int InitCommand();
    int CreateConfitNetwork();
    int InitBft();
    void CreateNewTx();
    void CreateNewElectBlock();
    int SetPriAndPubKey(const std::string& prikey);
    int InitBlock(const common::Config& conf);

    static const uint32_t kDefaultUdpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultUdpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kTestCreateAccountPeriod = 50u * 1000u;
    static const int64_t kTestNewElectPeriod = 10ll * 1000ll * 1000ll;

    common::Config conf_;
    transport::TransportPtr transport_{ nullptr };
    bool inited_{ false };
    std::mutex init_mutex_;
    Command cmd_;
    elect::ElectManager elect_mgr_;
    common::Tick test_new_account_tick_;
    common::Tick test_new_elect_tick_;
    bool ec_block_ok_{ false };

    DISALLOW_COPY_AND_ASSIGN(NetworkInit);
};

}  // namespace init

}  // namespace lego
