#include "stdafx.h"

#include "init/command.h"
#include "client/vpn_client.h"

// caller keep thread safe
static char res_data[20480] = { 0 };

char* init_network(
        const char* local_ip,
        uint16_t local_port,
        const char* bootstrap,
        const char* conf_path,
        const char* log_path,
        const char* log_conf_path) {
    auto res = lego::client::VpnClient::Instance()->Init(
            local_ip,
            local_port,
            bootstrap,
            conf_path,
            log_path,
            log_conf_path);
    if (res.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }
    memcpy(res_data, res.c_str(), res.size());
    res_data[res.size()] = '\0';
    return (char*)res_data;
}

char* get_vpn_nodes(
        const char* country,
        uint32_t count,
        bool route) {
    std::vector<lego::client::VpnServerNodePtr> nodes;
    lego::client::VpnClient::Instance()->GetVpnServerNodes(
            country,
            count,
            route,
            nodes);
    if (nodes.empty()) {
        return (char*)("ERROR");
    }

    std::string vpn_svr = "";
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        vpn_svr += nodes[i]->ip + ":";
        vpn_svr += std::to_string(nodes[i]->svr_port) + ":";
        vpn_svr += std::to_string(nodes[i]->route_port) + ":";
        vpn_svr += nodes[i]->seckey + ":";
        vpn_svr += nodes[i]->pubkey + ":";
        vpn_svr += nodes[i]->dht_key + ":";
        if (i != nodes.size() - 1) {
            vpn_svr += ",";
        }
    }
    if (vpn_svr.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }
    memcpy(res_data, vpn_svr.c_str(), vpn_svr.size());
    res_data[vpn_svr.size()] = '\0';
    return (char*)res_data;
}

int get_socket() {
    return lego::client::VpnClient::Instance()->GetSocket();
}

char* transactions(uint32_t begin, uint32_t len) {
    std::string res = lego::client::VpnClient::Instance()->Transactions(begin, len);
    if (res.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }

    if (res.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }
    memcpy(res_data, res.c_str(), res.size());
    res_data[res.size()] = '\0';
    return (char*)res_data;
}

int64_t get_balance() {
    return lego::client::VpnClient::Instance()->GetBalance();
}

int reset_transport(const std::string& ip, uint16_t port) {
    return lego::client::VpnClient::Instance()->ResetTransport(ip, port);
}

char* get_public_key() {
    std::string res = lego::client::VpnClient::Instance()->GetPublicKey();
    if (res.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }
    memcpy(res_data, res.c_str(), res.size());
    res_data[res.size()] = '\0';
    return (char*)res_data;
}

char* vpn_login(
        const char* svr_account,
        const char* route_str) {
    std::vector<std::string> route_vec;
    std::string res;
    lego::client::VpnClient::Instance()->VpnLogin(svr_account, route_vec, res);
    if (res.size() >= sizeof(res_data) - 1) {
        return (char*)("ERROR");
    }
    memcpy(res_data, res.c_str(), res.size());
    res_data[res.size()] = '\0';
    return (char*)res_data;
}

void use_cmd() {
    lego::init::Command cmd;
    if (!cmd.Init(false, true, false)) {
        std::cout << "init cmd failed!" << std::endl;
        return;
    }
    cmd.Run();
}

void create_account() {
	std::string gid;
	lego::client::VpnClient::Instance()->Transaction("", 0, gid);
}
