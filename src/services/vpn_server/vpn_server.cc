#include "services/vpn_server/vpn_server.h"

namespace lego {

namespace vpn {

void VpnServer::signal_cb(EV_P_ ev_signal* w, int revents) {

}

void VpnServer::accept_cb(EV_P_ ev_io* w, int revents) {

}

void VpnServer::server_send_cb(EV_P_ ev_io* w, int revents) {

}

void VpnServer::server_recv_cb(EV_P_ ev_io* w, int revents) {

}

void VpnServer::remote_recv_cb(EV_P_ ev_io* w, int revents) {

}

void VpnServer::remote_send_cb(EV_P_ ev_io* w, int revents) {

}

void VpnServer::server_timeout_cb(EV_P_ ev_timer* watcher, int revents) {

}

remote_t* VpnServer::new_remote(int fd) {
    return NULL;
}

server_t* VpnServer::new_server(int fd, listen_ctx_t* listener) {
    return NULL;
}

remote_t* VpnServer::connect_to_remote(
        EV_P_ struct addrinfo* res,
        server_t* server) {
    return NULL;
}

void VpnServer::free_remote(remote_t* remote) {

}

void VpnServer::close_and_free_remote(EV_P_ remote_t* remote) {

}

void VpnServer::free_server(server_t* server) {

}

void VpnServer::close_and_free_server(EV_P_ server_t* server) {

}

void VpnServer::resolv_cb(struct sockaddr* addr, void* data) {

}

void VpnServer::resolv_free_cb(void* data) {

}

VpnServer::VpnServer() {

}

VpnServer::~VpnServer() {

}

}  // namespace vpn

}  // namespace lego
