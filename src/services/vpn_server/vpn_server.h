#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#endif
#include <libcork/core.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "ssr/netutils.h"
#include "ssr/utils.h"
#include "ssr/acl.h"
#include "ssr/plugin.h"
#include "ssr/server.h"
#include "ssr/winsock.h"

#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

class VpnServer {
public:
    static void signal_cb(EV_P_ ev_signal* w, int revents);
    static void accept_cb(EV_P_ ev_io* w, int revents);
    static void server_send_cb(EV_P_ ev_io* w, int revents);
    static void server_recv_cb(EV_P_ ev_io* w, int revents);
    static void remote_recv_cb(EV_P_ ev_io* w, int revents);
    static void remote_send_cb(EV_P_ ev_io* w, int revents);
    static void server_timeout_cb(EV_P_ ev_timer* watcher, int revents);
    static remote_t* new_remote(int fd);
    static server_t* new_server(int fd, listen_ctx_t* listener);
    static remote_t* connect_to_remote(
            EV_P_ struct addrinfo* res,
            server_t* server);
    static void free_remote(remote_t* remote);
    static void close_and_free_remote(EV_P_ remote_t* remote);
    static void free_server(server_t* server);
    static void close_and_free_server(EV_P_ server_t* server);
    static void resolv_cb(struct sockaddr* addr, void* data);
    static void resolv_free_cb(void* data);

    VpnServer();
    ~VpnServer();

private:
    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

}  // namespace vpn

}  // namespace lego
