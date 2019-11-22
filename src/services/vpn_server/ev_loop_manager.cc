#include "stdafx.h"
#include "services/vpn_server/ev_loop_manager.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include  <netinet/in.h>
#include <netinet/tcp.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "ssr/netutils.h"
#include "ssr/crypto.h"
#include "ssr/utils.h"
#include "ssr/acl.h"
#include "ssr/plugin.h"
#include "ssr/winsock.h"
#include "ssr/stream.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

#ifndef MAX_FRAG
#define MAX_FRAG 1
#endif

#ifndef CONNECT_IN_PROGRESS
#define CONNECT_IN_PROGRESS 115
#endif // !CONNECT_IN_PROGRESS


#ifdef USE_NFCONNTRACK_TOS

#ifndef MARK_MAX_PACKET
#define MARK_MAX_PACKET 10
#endif

#ifndef MARK_MASK_PREFIX
#define MARK_MASK_PREFIX 0xDC00
#endif

#endif

#ifdef __cplusplus
}
#endif

namespace lego {

namespace vpn {

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
#ifndef __MINGW32__
static struct ev_signal sigchld_watcher;
#else
static struct plugin_watcher_t {
    ev_io io;
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif

static void SignalCallback(struct ev_loop* loop, ev_signal *w, int revents) {
    std::cout << "signal catched and now exit." << std::endl;
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
            } else {
                return;
            }
#endif
        case SIGINT:
        case SIGTERM:
            ev_signal_stop(loop, &sigint_watcher);
            ev_signal_stop(loop, &sigterm_watcher);
#ifndef __MINGW32__
            ev_signal_stop(loop, &sigchld_watcher);
#else
            ev_io_stop(loop, &plugin_watcher.io);
#endif
            ev_unloop(loop, EVUNLOOP_ALL);
        }
    }
}

static void InitSignal(struct ev_loop* loop) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    ev_signal_init(&sigint_watcher, SignalCallback, SIGINT);
    ev_signal_init(&sigterm_watcher, SignalCallback, SIGTERM);
    ev_signal_start(loop, &sigint_watcher);
    ev_signal_start(loop, &sigterm_watcher);
    ev_signal_init(&sigchld_watcher, SignalCallback, SIGCHLD);
    ev_signal_start(loop, &sigchld_watcher);
}

static void StartVpn() {
    ev_run(EvLoopManager::Instance()->loop(), 0);
}

EvLoopManager::EvLoopManager() {
    InitLoop();
}

EvLoopManager::~EvLoopManager() {
    resolv_shutdown(EvLoopManager::Instance()->loop());
}

EvLoopManager* EvLoopManager::Instance() {
    static EvLoopManager ins;
    return &ins;
}

void EvLoopManager::InitLoop() {
    loop_ = EV_DEFAULT;
    resolv_init(loop_, NULL, 0);
    InitSignal(loop_);
    loop_thread_ = std::make_shared<std::thread>(&StartVpn);
}

}  // namespace vpn

}  // namespace lego
