#include "stdafx.h"
#include "services/vpn_server/vpn_route.h"
#include "common/string_utils.h"

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

#include "common/encode.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/country_code.h"
#include "ip/ip_with_country.h"
#include "client/trans_client.h"
#include "contract/contract_utils.h"
#include "security/crypto_utils.h"
#include "security/aes.h"
#include "services/account_with_secret.h"
#include "sync/key_value_sync.h"
#include "network/universal_manager.h"
#include "network/route.h"
#include "network/dht_manager.h"
#include "dht/base_dht.h"
#include "block/proto/block.pb.h"
#include "block/proto/block_proto.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "services/vpn_server/ev_loop_manager.h"
#include "services/vpn_server/vpn_server.h"

using namespace lego;

static void AcceptCallback(EV_P_ ev_io *w, int revents);
static void ServerSendCallback(EV_P_ ev_io *w, int revents);
static void ServerRecvCallback(EV_P_ ev_io *w, int revents);
static void RemoteRecvCallback(EV_P_ ev_io *w, int revents);
static void RemoteSendCallback(EV_P_ ev_io *w, int revents);
static void ServerTimeoutCallback(EV_P_ ev_timer *watcher, int revents);

static remote_t *NewRemote(int fd);
static server_t *NewServer(int fd, listen_ctx_t *listener);
static remote_t *ConnectToRemote(EV_P_ struct addrinfo *res, server_t *server);

static void FreeRemote(remote_t *remote);
static void CloseAndFreeRemote(EV_P_ remote_t *remote);
static void FreeServer(server_t *server);
static void CloseAndFreeServer(EV_P_ server_t *server);

// static crypto_t *crypto;

static int acl = 0;
static int mode = TCP_ONLY;
static int ipv6first = 0;
static int fast_open = 1;
static int no_delay = 1;
static int ret_val = 0;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
extern int use_syslog;

#ifndef __MINGW32__SetFastopen
static ev_timer stat_update_watcher;
#endif

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

static const uint32_t kMaxConnectAccount = 1024u;  // single server just 1024 user

static void FreeConnections(struct ev_loop *loop, struct cork_dllist* connections) {
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        CloseAndFreeServer(loop, server);
        CloseAndFreeRemote(loop, remote);
    }
}

static char * GetPeerName(int fd) {
    static char peer_name[INET6_ADDRSTRLEN] = { 0 };
    struct sockaddr_storage addr;
    socklen_t len = sizeof(struct sockaddr_storage);
    memset(&addr, 0, len);
    memset(peer_name, 0, INET6_ADDRSTRLEN);
    int err = getpeername(fd, (struct sockaddr *)&addr, &len);
    if (err == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &s->sin_addr, peer_name, INET_ADDRSTRLEN);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &s->sin6_addr, peer_name, INET6_ADDRSTRLEN);
        }
    } else {
        return NULL;
    }
    return peer_name;
}

static void StopServer(EV_P_ server_t *server) {
    server->stage = STAGE_STOP;
}

static void ReportAddr(int fd, const char *info) {
    char *peer_name;
    peer_name = GetPeerName(fd);
    if (peer_name != NULL) {
        LOGE("failed to handshake with %s: %s", peer_name, info);
    }
}

static int SetFastopen(int fd) {
    int s = 0;
#ifdef TCP_FASTOPEN
    if (fast_open) {
#if defined(__APPLE__) || defined(__MINGW32__)
        int opt = 1;
#else
        int opt = 5;
#endif
        s = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

        if (s == -1) {
            if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
                LOGE("fast open is not supported on this platform");
                fast_open = 0;
            } else {
                ERROR("setsockopt");
            }
        }
    }
#endif
    return s;
}

#ifndef __MINGW32__
static int SetNonblocking(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

static int CreateAndBind(const char *host, const char *port, int mptcp) {
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    result = NULL;

    s = getaddrinfo(host, port, &hints, &result);

    if (s != 0) {
        LOGE("failed to resolve server name %s", host);
        return -1;
    }

    if (result == NULL) {
        LOGE("Cannot bind");
        return -1;
    }

    rp = result;

    /*
        * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
        * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
        * return a list of addresses to listen on, but it is impossible to listen on
        * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
        */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int opt = host ? 1 : 0;
            setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (mptcp == 1) {
            int i = 0;
            while ((mptcp = mptcp_enabled_values[i]) > 0) {
                int err = setsockopt(listen_sock, IPPROTO_TCP, mptcp, &opt, sizeof(opt));
                if (err != -1) {
                    break;
                }
                i++;
            }
            if (mptcp == 0) {
                ERROR("failed to enable multipath TCP");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
            FATAL("failed to bind address");
        }

        close(listen_sock);
        listen_sock = -1;
    }
    freeaddrinfo(result);
    return listen_sock;
}

static remote_t * ConnectToRemote(EV_P_ struct addrinfo *res, server_t *server) {
    int sockfd;
#ifdef SET_INTERFACE
    const char *iface = server->listen_ctx->iface;
#endif

    if (acl) {
        char ipstr[INET6_ADDRSTRLEN];
        memset(ipstr, 0, INET6_ADDRSTRLEN);

        if (res->ai_addr->sa_family == AF_INET) {
            struct sockaddr_in s;
            memcpy(&s, res->ai_addr, sizeof(struct sockaddr_in));
            inet_ntop(AF_INET, &s.sin_addr, ipstr, INET_ADDRSTRLEN);
        }
        else if (res->ai_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 s;
            memcpy(&s, res->ai_addr, sizeof(struct sockaddr_in6));
            inet_ntop(AF_INET6, &s.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        }

        if (outbound_block_match_host(ipstr) == 1) {
            return NULL;
        }
    }

    // initialize remote socks
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // setup remote socks

    if (SetNonblocking(sockfd) == -1)
        ERROR("SetNonblocking");

#ifdef SET_INTERFACE
    if (iface) {
        if (setinterface(sockfd, iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            std::cout << "setinterface return null" << std::endl;
            return NULL;
    }
}
#endif

    remote_t *remote = NewRemote(sockfd);

    if (fast_open) {
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
        int s = -1;
        s = sendto(sockfd, server->buf->data, server->buf->len,
            MSG_FASTOPEN, res->ai_addr, res->ai_addrlen);
#elif defined(TCP_FASTOPEN_WINSOCK)
        DWORD s = -1;
        DWORD err = 0;
        do {
            int optval = 1;
            // Set fast open option
            if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN,
                &optval, sizeof(optval)) != 0) {
                ERROR("setsockopt");
                break;
            }
            // Load ConnectEx function
            LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
            if (ConnectEx == NULL) {
                LOGE("Cannot load ConnectEx() function");
                err = WSAENOPROTOOPT;
                break;
            }
            // ConnectEx requires a bound socket
            if (winsock_dummybind(sockfd, res->ai_addr) != 0) {
                ERROR("bind");
                break;
            }
            // Call ConnectEx to send data
            memset(&remote->olap, 0, sizeof(remote->olap));
            remote->connect_ex_done = 0;
            if (ConnectEx(sockfd, res->ai_addr, res->ai_addrlen,
                server->buf->data, server->buf->len,
                &s, &remote->olap)) {
                remote->connect_ex_done = 1;
                break;
            }
            // XXX: ConnectEx pending, check later in remote_send
            if (WSAGetLastError() == ERROR_IO_PENDING) {
                err = CONNECT_IN_PROGRESS;
                break;
            }
            ERROR("ConnectEx");
        } while (0);
        // Set error number
        if (err) {
            SetLastError(err);
}
#else
        int s = -1;
#if defined(TCP_FASTOPEN_CONNECT)
        int optval = 1;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
            (void *)&optval, sizeof(optval)) < 0)
            FATAL("failed to set TCP_FASTOPEN_CONNECT");
        s = connect(sockfd, res->ai_addr, res->ai_addrlen);
#elif defined(CONNECT_DATA_IDEMPOTENT)
        struct sockaddr_in sa;
        memcpy(&sa, res->ai_addr, sizeof(struct sockaddr_in));
        sa.sin_len = sizeof(struct sockaddr_in);
        sa_endpoints_t endpoints;
        memset((char *)&endpoints, 0, sizeof(endpoints));
        endpoints.sae_dstaddr = (struct sockaddr *)&sa;
        endpoints.sae_dstaddrlen = res->ai_addrlen;

        s = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_DATA_IDEMPOTENT,
            NULL, 0, NULL, NULL);
#else
        FATAL("fast open is not enabled in this build");
#endif
        if (s == 0)
            s = send(sockfd, server->buf->data, server->buf->len, 0);
#endif
        if (s == -1) {
            if (errno == CONNECT_IN_PROGRESS) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            }
            else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("fast_open_connect");
            }
        } else {
            server->buf->idx += s;
            server->buf->len -= s;
        }
    }

    if (!fast_open) {
        int r = connect(sockfd, res->ai_addr, res->ai_addrlen);

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            CloseAndFreeRemote(EV_A_ remote);
            return NULL;
        }
    }

    return remote;
}

#ifdef USE_NFCONNTRACK_TOS
int SetMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    server_t *server = (server_t *)data;
    struct dscptracker *tracker = server->tracker;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (setsockopt(server->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

void ConntrackQuery(server_t *server) {
    struct dscptracker *tracker = server->tracker;
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, SetMarkDscpCallback, (void *)server);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(errno));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

void SetTosFromConnmark(remote_t *remote, server_t *server) {
    if (server->tracker && server->tracker->ct) {
        if (server->tracker->mark == 0 && server->tracker->packet_count < MARK_MAX_PACKET) {
            server->tracker->packet_count++;
            ConntrackQuery(server);
        }
    } else {
        socklen_t len;
        struct sockaddr_storage sin;
        len = sizeof(sin);
        if (getsockname(remote->fd, (struct sockaddr *)&sin, &len) == 0) {
            struct sockaddr_storage from_addr;
            len = sizeof from_addr;
            if (getpeername(remote->fd, (struct sockaddr *)&from_addr, &len) == 0) {
                if ((server->tracker = (struct dscptracker *)ss_malloc(sizeof(struct dscptracker)))) {
                    if ((server->tracker->ct = nfct_new())) {
                        // Build conntrack query SELECT
                        if (from_addr.ss_family == AF_INET) {
                            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
                            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin_port);
                        } else if (from_addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
                            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET6);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin6_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin6_port);
                        }
                        nfct_set_attr_u8(server->tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
                        ConntrackQuery(server);
                    } else {
                        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
                        server->tracker->ct = NULL;
                    }
                }
            }
        }
    }
}

#endif

static void ServerRecvCallback(EV_P_ ev_io *w, int revents) {
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server = server_recv_ctx->server;
    remote_t *remote = NULL;

    buffer_t *buf = server->buf;

    if (server->stage == STAGE_STREAM) {
        remote = server->remote;
        buf = remote->buf;
    }

    ssize_t r = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);
    if (r == 0) {
        // connection closed
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        } else {
            ERROR("server recv");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    if (server->stage == STAGE_STOP) {
        return;
    }

    buf->len = r;
    if (server->stage == STAGE_STREAM) {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            } else {
                ERROR("server_recv_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
        } else if (s < static_cast<int>(remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    } else if (server->stage == STAGE_INIT) {
        int offset = 0;
        int need_query = 0;
        char host[255] = { 0 };
        struct addrinfo info;
        struct sockaddr_storage storage;
        memset(&info, 0, sizeof(struct addrinfo));
        memset(&storage, 0, sizeof(struct sockaddr_storage));
        struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
        size_t in_addr_len = sizeof(struct in_addr);
        addr->sin_family = AF_INET;
        if (server->buf->len >= in_addr_len + 3) {
            memcpy(&addr->sin_addr, server->buf->data + offset, in_addr_len);
            inet_ntop(AF_INET, (const void *)(server->buf->data + offset), host, INET_ADDRSTRLEN);
            offset += in_addr_len;
        } else {
            ReportAddr(server->fd, "invalid length for ipv4 address");
            StopServer(EV_A_ server);
            return;
        }
        memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
        info.ai_family = AF_INET;
        info.ai_socktype = SOCK_STREAM;
        info.ai_protocol = IPPROTO_TCP;
        info.ai_addrlen = sizeof(struct sockaddr_in);
        info.ai_addr = (struct sockaddr *)addr;

        if (offset == 0) {
            ReportAddr(server->fd, "invalid address type");
            StopServer(EV_A_ server);
            return;
        }

        offset += 2;
        if (static_cast<int>(server->buf->len) < offset) {
            ReportAddr(server->fd, "invalid request length");
            StopServer(EV_A_ server);
            return;
        } else {
            server->buf->len -= offset;
            memmove(server->buf->data, server->buf->data + offset, server->buf->len);

//             if (server->country_code == common::CountryCode::CN) {
//                 size_t header_offset = lego::security::kPublicKeySize * 2;
//                 if (server->buf->len >= header_offset) {
//                     std::string pubkey = common::Encode::HexDecode(
//                             std::string((char*)buf->data, header_offset));
//                     std::string account = lego::network::GetAccountAddressByPublicKey(pubkey);
//                     if (!lego::vpn::VpnServer::Instance()->ClientAccountValid(account)) {
//                         send(server->fd,
//                                 lego::common::kCountryInvalid.c_str(),
//                                 lego::common::kCountryInvalid.size(),
//                                 0);
//                         CloseAndFreeServer(EV_A_ server);
//                         return;
//                     }
//                 }
//             }
        }

        remote_t *remote = ConnectToRemote(EV_A_ & info, server);
        if (remote == NULL) {
            LOGE("connect error");
            CloseAndFreeServer(EV_A_ server);
            return;
        } else {
            server->remote = remote;
            remote->server = server;

            if (server->buf->len > 0) {
                brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
                memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                    server->buf->len);
                remote->buf->len = server->buf->len;
                remote->buf->idx = 0;
                server->buf->len = 0;
                server->buf->idx = 0;
            }

            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    }
}

static void ServerSendCallback(EV_P_ ev_io *w, int revents) {
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server = server_send_ctx->server;
    remote_t *remote = server->remote;

    if (remote == NULL) {
        LOGE("invalid server");
        CloseAndFreeServer(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
            server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        } else if (s < static_cast<int>(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
                return;
            }
        }
    }
}

static void ServerTimeoutCallback(EV_P_ ev_timer *watcher, int revents) {
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);
    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    CloseAndFreeRemote(EV_A_ remote);
    CloseAndFreeServer(EV_A_ server);
}

static void RemoteRecvCallback(EV_P_ ev_io *w, int revents) {
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote = remote_recv_ctx->remote;
    server_t *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        CloseAndFreeRemote(EV_A_ remote);
        return;
    }

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);
    if (r == 0) {
        // connection closed
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    // Ignore any new packet if the server is stopped
    if (server->stage == STAGE_STOP) {
        return;
    }

    server->buf->len = r;
#ifdef USE_NFCONNTRACK_TOS
    SetTosFromConnmark(remote, server);
#endif
    int s = send(server->fd, server->buf->data, server->buf->len, 0);
    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    } else if (s < static_cast<int>(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void RemoteSendCallback(EV_P_ ev_io *w, int revents) {
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote = remote_send_ctx->remote;
    server_t *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        CloseAndFreeRemote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                    &numBytes, FALSE, &flags)) {
                    remote->buf->len -= numBytes;
                    remote->buf->idx = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    CloseAndFreeRemote(EV_A_ remote);
                    CloseAndFreeServer(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);

        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);

        if (r == 0) {
            // connection connected, stop the request timeout timer
            ev_timer_stop(EV_A_ & server->recv_ctx->watcher);

            remote_send_ctx->connected = 1;

            if (remote->buf->len == 0) {
                server->stage = STAGE_STREAM;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
        } else {
            ERROR("getpeername");
            // not connected
            CloseAndFreeRemote(EV_A_ remote);
            CloseAndFreeServer(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        CloseAndFreeRemote(EV_A_ remote);
        CloseAndFreeServer(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
            remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        } else if (s < static_cast<int>(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                CloseAndFreeRemote(EV_A_ remote);
                CloseAndFreeServer(EV_A_ server);
            }
            return;
        }
    }
}

static remote_t * NewRemote(int fd) {
    remote_t *remote = (remote_t*)ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = (remote_ctx_t*)ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = (remote_ctx_t*)ss_malloc(sizeof(remote_ctx_t));
    remote->buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd = fd;
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->server = NULL;

    ev_io_init(&remote->recv_ctx->io, RemoteRecvCallback, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, RemoteSendCallback, fd, EV_WRITE);

    return remote;
}

static void FreeRemote(remote_t *remote) {
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void CloseAndFreeRemote(EV_P_ remote_t *remote) {
    if (remote != NULL) {
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        FreeRemote(remote);
    }
}

static server_t * NewServer(int fd, listen_ctx_t *listener) {
    server_t *server;
    server = (server_t*)ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = (server_ctx_t*)ss_malloc(sizeof(server_ctx_t));
    server->buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    server->fd = fd;
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    server->stage = STAGE_INIT;
    server->frag = 0;
    server->query = NULL;
    server->listen_ctx = listener;
    server->remote = NULL;
    server->svr_item = listener->svr_item;
    server->e_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));

    int request_timeout = std::min(MAX_REQUEST_TIMEOUT, listener->timeout)
        + rand() % MAX_REQUEST_TIMEOUT;

    ev_io_init(&server->recv_ctx->io, ServerRecvCallback, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, ServerSendCallback, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, ServerTimeoutCallback,
        request_timeout, 0);

    cork_dllist_add(&server->svr_item->connections, &server->entries);

    return server;
}

static void FreeServer(server_t *server) {
#ifdef USE_NFCONNTRACK_TOS
    if (server->tracker) {
        struct dscptracker *tracker = server->tracker;
        struct nf_conntrack *ct = server->tracker->ct;
        server->tracker = NULL;
        if (ct) {
            nfct_destroy(ct);
        }
        free(tracker);
    }
#endif
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }

    crypto_t* tmp_crypto = NULL;
    if (server->client_ptr != nullptr) {
        tmp_crypto = server->client_ptr->crypto;
    }

    if (server->e_ctx != NULL) {
        if (tmp_crypto != NULL) {
            tmp_crypto->ctx_release(server->e_ctx);
        }
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        if (tmp_crypto != NULL) {
            tmp_crypto->ctx_release(server->d_ctx);
        }
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }

    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void CloseAndFreeServer(EV_P_ server_t *server) {
    if (server != NULL) {
        if (server->query != NULL) {
            server->query->server = NULL;
            server->query = NULL;
        }
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        close(server->fd);
        FreeServer(server);
    }
}

#ifdef __MINGW32__
static void plugin_watcher_cb(EV_P_ ev_io *w, int revents) {
    char buf[1];
    SOCKET fd = accept(plugin_watcher.fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    ret_val = -1;
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}
#endif

static void AcceptCallback(EV_P_ ev_io *w, int revents) {
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    char *peer_name = GetPeerName(serverfd);
    if (peer_name != NULL) {
        if (acl) {
            if ((get_acl_mode() == BLACK_LIST && acl_match_host(peer_name) == 1)
                || (get_acl_mode() == WHITE_LIST && acl_match_host(peer_name) >= 0)) {
                LOGE("Access denied from %s", peer_name);
                close(serverfd);
                return;
            }
        }
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    SetNonblocking(serverfd);

    server_t *server = NewServer(serverfd, listener);
    server->country_code = lego::ip::IpWithCountry::Instance()->GetCountryUintCode(peer_name);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);

    auto login_item = std::make_shared<lego::vpn::LoginCountryItem>();
    login_item->country = (uint32_t)server->country_code;
    login_item->count = 0;
    lego::vpn::VpnRoute::Instance()->login_country_queue().push(login_item);
}

static int StartTcpServer(
        const std::string& host,
        uint16_t port,
        listen_ctx_t* listen_ctx) {
    const char* remote_port = (char*)std::to_string(port).c_str();

    int listenfd;
    listenfd = CreateAndBind(host.c_str(), remote_port, 0);
    if (listenfd == -1) {
        return -1;
    }

    if (listen(listenfd, SSMAXCONN) == -1) {
        LOGI("listen()");
        return -1;
    }
    SetFastopen(listenfd);
    SetNonblocking(listenfd);

    listen_ctx->timeout = 60;
    listen_ctx->fd = listenfd;
    listen_ctx->iface = NULL;
    listen_ctx->loop = vpn::EvLoopManager::Instance()->loop();
    listen_ctx->svr_item = std::make_shared<server_item_t>();
    ev_io_init(&listen_ctx->io, AcceptCallback, listenfd, EV_READ);
    ev_io_start(vpn::EvLoopManager::Instance()->loop(), &listen_ctx->io);
    return 0;
}

static void StopRoute(listen_ctx_t* listen_ctx) {
    ev_io_stop(vpn::EvLoopManager::Instance()->loop(), &listen_ctx->io);
    close(listen_ctx->fd);
    FreeConnections(vpn::EvLoopManager::Instance()->loop(), &listen_ctx->svr_item->connections);
#ifdef __MINGW32__
        if (plugin_watcher.valid) {
            closesocket(plugin_watcher.fd);
        }

        winsock_cleanup();
#endif
}

namespace lego {

namespace vpn {

VpnRoute::VpnRoute() {
    now_day_timestamp_ = common::TimeUtils::TimestampDays();
}

VpnRoute::~VpnRoute() {}

VpnRoute* VpnRoute::Instance() {
    static VpnRoute ins;
    return &ins;
}

void VpnRoute::Stop() {
    while (!listen_ctx_queue_.empty()) {
        auto listen_ctx_ptr = listen_ctx_queue_.front();
        listen_ctx_queue_.pop_front();
        StopRoute(listen_ctx_ptr.get());
    }
}

int VpnRoute::Init() {
    RotationServer();
    CheckLoginClient();
    if (listen_ctx_queue_.empty()) {
        std::cout << "start vpn route server failed!" << std::endl;
        return kVpnsvrError;
    }

    return kVpnsvrSuccess;
}

void VpnRoute::StartMoreServer() {
    auto vpn_svr_dht = network::DhtManager::Instance()->GetDht(network::kVpnRouteNetworkId);
    if (vpn_svr_dht == nullptr) {
        return;
    }

    auto now_timestamp_days = common::TimeUtils::TimestampDays();
    std::vector<uint16_t> valid_port;
    for (int i = -1; i <= 1; ++i) {
        auto port = common::GetVpnRoutePort(
                vpn_svr_dht->local_node()->dht_key,
                now_timestamp_days + i);
        if (started_port_set_.find(port) != started_port_set_.end()) {
            continue;
        }
        valid_port.push_back(port);
    }

    if (valid_port.empty()) {
        return;
    }

    for (uint32_t i = 0; i < valid_port.size(); ++i) {
        std::shared_ptr<listen_ctx_t> listen_ctx_ptr = std::make_shared<listen_ctx_t>();
        if (StartTcpServer(
                common::GlobalInfo::Instance()->config_local_ip(),
                valid_port[i],
                listen_ctx_ptr.get()) == 0) {
            listen_ctx_ptr->vpn_port = valid_port[i];
            cork_dllist_init(&listen_ctx_ptr->svr_item->connections);
            last_listen_ptr_ = listen_ctx_ptr;
            listen_ctx_queue_.push_back(listen_ctx_ptr);
            started_port_set_.insert(valid_port[i]);
            std::cout << "start vpn route port: " << valid_port[i] << std::endl;
        }
    }

    while (listen_ctx_queue_.size() >= common::kMaxRotationCount) {
        auto listen_item = listen_ctx_queue_.front();
        listen_ctx_queue_.pop_front();
        StopRoute(listen_item.get());
    }
}

void VpnRoute::SendNewClientLogin(const std::string& val) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }

    std::string tmp_key = common::kVpnClientLoginAttr + now_day_timestamp;
    std::map<std::string, std::string> attrs{
        {tmp_key, val},
    };

    std::string gid;
    lego::client::TransactionClient::Instance()->Transaction(
            common::Encode::HexDecode(common::kVpnLoginManageAccount),
            0,
            contract::kVpnClientLoginManager,
            attrs,
            common::kConsensusKeyValue,
            gid);
}

void VpnRoute::CheckLoginClient() {
    LoginCountryItemPtr login_client = nullptr;
    while (login_country_queue_.pop(&login_client)) {
        if (login_client != nullptr) {
            auto iter = client_map_.find(login_client->country);
            if (iter != client_map_.end()) {
                ++(iter->second->count);
                continue;
            }

            login_client->count = 1;
            client_map_[login_client->country] = login_client;
        }
    }

    ++check_login_tiems_;
    auto now_day_timestamp = common::TimeUtils::TimestampDays();
    if (now_day_timestamp_ != now_day_timestamp) {
        std::string tmp_str = "";
        for (auto iter = client_map_.begin(); iter != client_map_.end(); ++iter) {
            tmp_str += (std::to_string(iter->first) + ":" +
                std::to_string(iter->second->count) + ",");
        }

        if (!tmp_str.empty()) {
            SendNewClientLogin(tmp_str);
        }

        now_day_timestamp_ = now_day_timestamp;
        check_login_tiems_ = 0;
        client_map_.clear();
    }

    if (check_login_tiems_ >= 6) {
        check_login_tiems_ = 0;
        std::string tmp_str = "";
        for (auto iter = client_map_.begin(); iter != client_map_.end(); ++iter) {
            tmp_str += (std::to_string(iter->first) + ":" +
                std::to_string(iter->second->count) + ",");
        }

        if (!tmp_str.empty()) {
            SendNewClientLogin(tmp_str);
        }
        client_map_.clear();
    }

    new_vpn_server_tick_.CutOff(
            kCheckLoginCLientPeriod,
            std::bind(&VpnRoute::CheckLoginClient, VpnRoute::Instance()));
}

void VpnRoute::RotationServer() {
    StartMoreServer();
    new_vpn_server_tick_.CutOff(
            common::kRotationPeriod,
            std::bind(&VpnRoute::RotationServer, VpnRoute::Instance()));
}

}  // namespace vpn

}  // namespace lego