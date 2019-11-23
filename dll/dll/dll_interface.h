#pragma once

#include <string>
#include <cstdint>
#include <vector>

__declspec(dllexport) char* init_network(
        const char* local_ip,
        uint16_t local_port,
        const char* bootstrap,
        const char* conf_path,
        const char* log_path,
        const char* log_conf_path);
__declspec(dllexport) char* get_vpn_nodes(
        const char* country,
        uint32_t count,
        bool route);
__declspec(dllexport) int get_socket();
__declspec(dllexport) char* transactions(uint32_t begin, uint32_t len);
__declspec(dllexport) int64_t get_balance();
__declspec(dllexport) char* get_public_key();
__declspec(dllexport) char* vpn_login(
        const char* svr_account,
        const char* route_vec);
__declspec(dllexport) void use_cmd();
__declspec(dllexport) void create_account();
__declspec(dllexport) char* check_version();
__declspec(dllexport) char* reset_private_key(const char* pri_key);
__declspec(dllexport) char* check_vip();
__declspec(dllexport) char* pay_for_vpn(const char* acc, const char* gid, int64_t amount);
