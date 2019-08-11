#include "init/command.h"

#include <iostream>
#include <memory>
#include <thread>

#include "common/split.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "dht/base_dht.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "bft/bft_manager.h"
#include "init/init_utils.h"
#include "client/vpn_client.h"

namespace lego {

namespace init {

Command::Command() {}

Command::~Command() {
    destroy_ = true;
}

bool Command::Init(bool first_node, bool show_cmd) {
    first_node_ = first_node;
    show_cmd_ = show_cmd;
    AddBaseCommands();
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
        GetVpnNodes();
    });
    AddCommand("tx", [this](const std::vector<std::string>& args) {
        std::string tx_gid;
        std::string to;
        if (args.size() > 0) {
            to = common::Encode::HexDecode(args[0]);
        }

        uint64_t amount = 0;
        if (args.size() > 1) {
            amount = common::StringUtil::ToUint64(args[1]);
        }
        lego::client::VpnClient::Instance()->Transaction(to, amount, tx_gid);
        while (lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid).empty()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100000ull));
        }
        std::cout << "success transaction from: "
                << common::Encode::HexEncode(common::GlobalInfo::Instance()->id())
                << " to: " << to << " , amount: " << amount << std::endl;
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

        client::TxInfoPtr block_ptr = nullptr;
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
    });
}

void Command::GetVpnNodes() {
    std::vector<lego::client::VpnServerNodePtr> nodes;
    lego::client::VpnClient::Instance()->GetVpnServerNodes("US", 2, nodes);
    std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->port
            << ", " << nodes[i]->encrypt_type << ", " << nodes[i]->passwd << std::endl;
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
    std::cout << "local: " << common::Encode::HexEncode(node->id) << ":" << node->id_hash
        << ", " << common::Encode::HexSubstr(node->dht_key) << ":" << node->dht_key_hash
        << ", " << node->public_ip << ":" << node->public_port << std::endl;
    for (auto iter = readonly_dht->begin(); iter != readonly_dht->end(); ++iter) {
        auto node = *iter;
        assert(node != nullptr);
        std::cout << common::Encode::HexEncode(node->id) << ":" << node->id_hash
            << ", " << common::Encode::HexSubstr(node->dht_key) << ":" << node->dht_key_hash
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
