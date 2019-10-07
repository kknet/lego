#pragma once

#include <string>
#include <cstdint>
#include <vector>

__declspec(dllexport) std::string init_network(
        const std::string& local_ip,
        uint16_t local_port,
        const std::string& bootstrap,
        const std::string& conf_path,
        const std::string& log_path,
        const std::string& log_conf_path);
__declspec(dllexport) std::string get_vpn_nodes(
        const std::string& country,
        uint32_t count,
        bool route,
        std::string& nodes_str);
__declspec(dllexport) int get_socket();
__declspec(dllexport) std::string transactions(uint32_t begin, uint32_t len);
__declspec(dllexport) int64_t get_balance();
__declspec(dllexport) int reset_transport(const std::string& ip, uint16_t port);
__declspec(dllexport) std::string get_public_key();
__declspec(dllexport) int vpn_login(
        const std::string& svr_account,
        const std::vector<std::string>& route_vec,
        std::string& login_gid);
__declspec(dllexport) void use_cmd();
