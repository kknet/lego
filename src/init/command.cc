#include "init/command.h"

#include <iostream>
#include <memory>
#include <thread>

#include "common/split.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "bft/bft_manager.h"
#include "init/init_utils.h"
#include "client/vpn_client.h"
#include "client/proto/client.pb.h"
#include "services/vpn_server/server.h"
#include "services/vpn_server/vpn_server.h"

namespace lego {

namespace init {

Command::Command() {}

Command::~Command() {
    destroy_ = true;
}

bool Command::Init(bool first_node, bool show_cmd, bool period_tick) {
    first_node_ = first_node;
    show_cmd_ = show_cmd;
    AddBaseCommands();
    if (period_tick) {
        tx_tick_.CutOff(kTransportTestPeriod, std::bind(&Command::TxPeriod, this));
    }
    return true;
}

void Command::Run() {
    Help();
    while (!destroy_) {
        if (!show_cmd_) {
            std::this_thread::sleep_for(std::chrono::microseconds(200000ll));
            continue;
        }

        std::cout << std::endl << std::endl << "cmd > ";
        std::string cmdline;
        std::getline(std::cin, cmdline);
        ProcessCommand(cmdline);
    }
}

void Command::ProcessCommand(const std::string& cmdline) {
    if (cmdline.empty()) {
        return;
    }

    std::string cmd;
    std::vector<std::string> args;
    try {
        common::Split line_split(cmdline.c_str(), ' ', cmdline.size());
        cmd = "";
        for (uint32_t i = 0; i < line_split.Count(); ++i) {
            if (strlen(line_split[i]) == 0) {
                continue;
            }

            if (cmd == "") {
                cmd = line_split[i];
            } else {
                args.push_back(line_split[i]);
            }
        }
    } catch (const std::exception& e) {
        INIT_WARN("Error processing command: %s", e.what());
    }

    std::unique_lock<std::mutex> lock(cmd_map_mutex_);
    auto it = cmd_map_.find(cmd);
    if (it == cmd_map_.end()) {
        std::cout << "Invalid command : " << cmd << std::endl;
    } else {
        (it->second)(args);
    }
}

void Command::AddCommand(const std::string& cmd_name, CommandFunction cmd_func) {
    assert(cmd_func);
    std::unique_lock<std::mutex> lock(cmd_map_mutex_);
    auto it = cmd_map_.find(cmd_name);
    if (it != cmd_map_.end()) {
        INIT_WARN("command(%s) exist and ignore new one", cmd_name.c_str());
        return;
    }
    cmd_map_[cmd_name] = cmd_func;
}

void Command::AddBaseCommands() {
    AddCommand("help", [this](const std::vector<std::string>& args) {
        Help();
    });
    AddCommand("prt", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }
        uint32_t network_id = common::StringUtil::ToUint32(args[0]);
        PrintDht(network_id);
    });
    AddCommand("mem", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }
        uint32_t network_id = common::StringUtil::ToUint32(args[0]);
        PrintMembers(network_id);
    });
    AddCommand("vn", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            GetVpnNodes(args[0]);
        } else {
            GetVpnNodes("US");
        }
    });
    AddCommand("rn", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            GetRouteNodes(args[0]);
        }
        else {
            GetRouteNodes("US");
        }
    });
    AddCommand("vh", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            VpnHeartbeat(args[0]);
        }
    });
    AddCommand("ltx", [this](const std::vector<std::string>& args) {
        std::cout << client::VpnClient::Instance()->Transactions(0, 10) << std::endl;
    });
    AddCommand("vl", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::vector<std::string> route_vec;
        route_vec.push_back("test_route1");
        route_vec.push_back("test_route2");
        std::string account = "test_account";
        std::string gid;
        std::cout << client::VpnClient::Instance()->VpnLogin(
                common::Encode::HexDecode(args[0]),
                route_vec,
                gid) << std::endl;
        std::cout << "gid:" << gid << std::endl;
    });
    AddCommand("vs", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        auto acc_item = std::make_shared<BandwidthInfo>(
                10, 10, common::Encode::HexDecode(args[0]));
        lego::vpn::VpnServer::Instance()->bandwidth_queue().push(acc_item);

    });
    AddCommand("tx", [this](const std::vector<std::string>& args) {
        std::string tx_gid;
        std::string to;
        if (args.size() > 0) {
            to = args[0];
        }

        uint64_t amount = 0;
        if (args.size() > 1) {
            amount = common::StringUtil::ToUint64(args[1]);
        }
        lego::client::VpnClient::Instance()->Transaction(to, amount, tx_gid);
        while (lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid).empty()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100000ull));
        }
        std::cout << "tx gid:" << tx_gid << " success transaction from: "
                << common::Encode::HexEncode(common::GlobalInfo::Instance()->id())
                << " to: " << args[0] << " , amount: " << amount << std::endl;
    });
    AddCommand("bg", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::string hash = args[0];
        bool is_gid = false;
        if (args.size() > 1) {
            is_gid = common::StringUtil::ToBool(args[1]);
        }

        std::shared_ptr<client::protobuf::Block> block_ptr = nullptr;
        if (is_gid) {
            block_ptr = lego::client::VpnClient::Instance()->GetBlockWithGid(hash);
        } else {
            block_ptr = lego::client::VpnClient::Instance()->GetBlockWithHash(hash);
        }

        while (block_ptr == nullptr) {
            std::this_thread::sleep_for(std::chrono::microseconds(100000ull));
            if (is_gid) {
                block_ptr = lego::client::VpnClient::Instance()->GetBlockWithGid(hash);
            } else {
                block_ptr = lego::client::VpnClient::Instance()->GetBlockWithHash(hash);
            }
        }
        std::cout << "get block info success." << std::endl;
        std::cout << "block height: " << block_ptr->height() << std::endl;
        std::cout << "block hash: " << common::Encode::HexEncode(block_ptr->hash()) << std::endl;
        std::cout << "prev hash: " << common::Encode::HexEncode(block_ptr->tx_block().prehash()) << std::endl;
        std::cout << "transaction size: " << block_ptr->tx_block().tx_list_size() << std::endl;
        auto tx_list = block_ptr->tx_block().tx_list();
        for (int32_t i = 0; i < tx_list.size(); ++i) {
            std::cout << "\ttransaction gid: " << common::Encode::HexEncode(tx_list[i].gid()) << std::endl;
            std::cout << "\tfrom: " << common::Encode::HexEncode(tx_list[i].from()) << std::endl;
            std::cout << "\tto: " << common::Encode::HexEncode(tx_list[i].to()) << std::endl;
            std::cout << "\tamount: " << tx_list[i].amount() << std::endl;
            std::cout << "\ttype: " << tx_list[i].type() << std::endl;
            std::cout << "\tattr size: " << tx_list[i].attr_size() << std::endl;
            for (int32_t j = 0; j < tx_list[i].attr_size(); ++j) {
                std::cout << "\t\t" << tx_list[i].attr(j).key() << ": " << tx_list[i].attr(j).value() << std::endl;
            }
            std::cout << std::endl;
        }
    });
}

void Command::TxPeriod() {
    const static std::vector<std::string> kToVec = {
        "ed8ff8be40cea693ccccdec322734efad3887c214d9b5b5d27e7eeb23f9bad57",
        "d13e2e80bfabf218571aa7d1e9d78725ac81a44c5ce1cdd26e26682f5fb074ea",
        "7ff1c9d61979ff5e628a462a12cf6bb37b0385999e4d38dba49b2f3b290cb629",
        "33db092901adfc31113bb4c8de4d02f71725ecab3cc6f80cbf17198a44d27042",
        "8362c14239913b0bba5cfde3077e7213f1dd63483b96c3a4d69c96b7bc880dd0",
        "562e22f17854a247bcb31b7593e3e7870de3e6185180f079bb7b9b3ff7d332ba",
        "1cbf2103db1fdb0257a4fed5fb4088ec0ee5ec092a16113acfd0d39b7fda32ef",
        "9933386363509f9cc38850819da15805c905b23ca0fe1b72e00167c733b612ad",
        "5ebd74cbdbb526380ff42ded6ec1e285b41f0adee552d7517c5bfd84ee4f893b",
        "eddfa882929c48b6021dfe2f44f7af49c6402c121965057f67fad275aec9e340",
        "07d2d95eb210cd897d255767e0e278d23e21193fbd3ba02452d4c0bf711f6a38",
        "46e404414a45abbb8375a07465445958a0485f692f3118e2e444b17c8b516bd2",
        "ed64f20aa64f4543162b7806c6205ae5655a469280531e58accd793f581387f4",
        "a67f5318d4355861b9fa4d8d7ebc346ae2154691ca7aaf90111e4d87f0e3254a",
        "72012a413fe07cc3fd6367489ce047e577f646e8c45cdf649bd23cb21c8b707e"
    };
    std::string to = kToVec[std::rand() % kToVec.size()];
    uint32_t amount = std::rand() % 100 + 10;
    std::string tx_gid;
    lego::client::VpnClient::Instance()->Transaction(to, amount, tx_gid);
    tx_tick_.CutOff(kTransportTestPeriod, std::bind(&Command::TxPeriod, this));
    std::cout << "tx gid:" << tx_gid << " success transaction from: "
        << common::Encode::HexEncode(common::GlobalInfo::Instance()->id())
        << " to: " << to << " , amount: " << amount << std::endl;
}

void Command::VpnHeartbeat(const std::string& dht_key) {
    client::VpnClient::Instance()->VpnHeartbeat(dht_key);
}

void Command::GetVpnNodes(const std::string& country) {
    std::vector<lego::client::VpnServerNodePtr> nodes;
    lego::client::VpnClient::Instance()->GetVpnServerNodes(country, 2, false, nodes);
    std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->svr_port
            << ", " << nodes[i]->svr_port << ", "
            << nodes[i]->seckey << ", "
            << nodes[i]->pubkey << ", "
            << nodes[i]->dht_key << std::endl;
    }
}

void Command::GetRouteNodes(const std::string& country) {
    std::vector<lego::client::VpnServerNodePtr> nodes;
    lego::client::VpnClient::Instance()->GetVpnServerNodes(country, 2, true, nodes);
    std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->svr_port
            << ", " << nodes[i]->svr_port << ", "
            << nodes[i]->seckey << ", "
            << nodes[i]->pubkey << ", "
            << nodes[i]->dht_key << std::endl;
    }
}

void Command::PrintMembers(uint32_t network_id) {
    auto mem_ptr = bft::BftManager::Instance()->GetNetworkMembers(network_id);
    if (mem_ptr != nullptr) {
        for (auto iter = mem_ptr->begin(); iter != mem_ptr->end(); ++iter) {
            std::cout << (*iter)->id << std::endl;
        }
    }
}

void Command::PrintDht(uint32_t network_id) {
    auto base_dht = network::DhtManager::Instance()->GetDht(network_id);
    if (!base_dht) {
        base_dht = network::UniversalManager::Instance()->GetUniversal(network_id);
    }

    if (!base_dht) {
        return;
    }
    dht::DhtPtr readonly_dht = base_dht->readonly_dht();
    auto node = base_dht->local_node();
    std::cout << "dht nnum: " << readonly_dht->size() + 1 << std::endl;
    std::cout << "local: " << common::Encode::HexEncode(node->id) << ":" << node->id_hash
        << ", " << common::Encode::HexSubstr(node->dht_key) << ":" << node->dht_key_hash
        << ", " << node->public_ip << ":" << node->public_port << std::endl;
    for (auto iter = readonly_dht->begin(); iter != readonly_dht->end(); ++iter) {
        auto node = *iter;
        assert(node != nullptr);
        auto country = common::global_code_to_country_map[
                dht::DhtKeyManager::DhtKeyGetCountry(node->dht_key)];
        std::cout << common::Encode::HexSubstr(node->id)
            << ", " << common::Encode::HexEncode(node->dht_key) << ", " << country
            << ", " << node->public_ip << ":" << node->public_port << std::endl;
    }
}

void Command::Help() {
    std::cout << "Allowed options:" << std::endl;
    std::cout << "\t-h [help]            print help info" << std::endl;
    std::cout << "\t-c [conf]            set config path" << std::endl;
    std::cout << "\t-v [version]         get bin version" << std::endl;
    std::cout << "\t-g [show_cmd]        show command" << std::endl;
    std::cout << "\t-p [peer]            bootstrap peer ip:port" << std::endl;
    std::cout << "\t-f [first]           1: first node 0: no" << std::endl;
    std::cout << "\t-a [address]         local ip" << std::endl;
    std::cout << "\t-l [listen_port]     local port" << std::endl;
    std::cout << "\t-d [db]              db path" << std::endl;
    std::cout << "\t-o [country]         country code" << std::endl;
    std::cout << "\t-n [network]         network id" << std::endl;
    std::cout << "\t-L [log]             log path" << std::endl;
}

}  // namespace init

}  // namespace lego
