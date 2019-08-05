#pragma once

#include <functional>
#include <vector>
#include <mutex>
#include <map>

#include "common/utils.h"

namespace lego {

namespace init {

typedef std::function<void(const std::vector<std::string>&)> CommandFunction;

class Command {
public:
    Command();
    ~Command();

    bool Init(bool first_node, bool show_cmd);
    void Run();
    void Destroy() { destroy_ = true; }
    void Help();

private:
    void ProcessCommand(const std::string& cmdline);
    void AddCommand(const std::string& cmd_name, CommandFunction cmd_func);
    void AddBaseCommands();
    void PrintDht(uint32_t network_id);
    void PrintMembers(uint32_t network_id);

    std::map<std::string, CommandFunction> cmd_map_;
    std::mutex cmd_map_mutex_;
    bool destroy_{ false };
    bool show_cmd_{ false };
    bool first_node_{ false };
};

}  // namespace init

}  // namespace lego
