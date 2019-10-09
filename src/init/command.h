#pragma once

#include <functional>
#include <vector>
#include <mutex>
#include <map>

#include "common/utils.h"
#include "common/tick.h"

namespace lego {

namespace init {

typedef std::function<void(const std::vector<std::string>&)> CommandFunction;

class Command {
public:
    Command();
    ~Command();

    bool Init(bool first_node, bool show_cmd, bool period_tick = false);
    void Run();
    void Destroy() { destroy_ = true; }
    void Help();

private:
    void ProcessCommand(const std::string& cmdline);
    void AddCommand(const std::string& cmd_name, CommandFunction cmd_func);
    void AddBaseCommands();
    void PrintDht(uint32_t network_id);
    void PrintMembers(uint32_t network_id);
    void GetVpnNodes(const std::string& country);
    void GetRouteNodes(const std::string& country);
    void TxPeriod();
	void VpnHeartbeat(const std::string& dht_key);
	void CreateNewVpnVersion(const std::string& version, const std::string& download_url);

	static const uint32_t kTransportTestPeriod = 1000 * 1000;
    std::map<std::string, CommandFunction> cmd_map_;
    std::mutex cmd_map_mutex_;
    bool destroy_{ false };
    bool show_cmd_{ false };
    bool first_node_{ false };
    common::Tick tx_tick_;
};

}  // namespace init

}  // namespace lego
