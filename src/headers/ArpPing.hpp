#define _GNU_SOURCE
#ifndef ARPING_HPP
#define ARPING_HPP

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h> 
#include <netdb.h>
#include <iomanip>
#include <net/if_arp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <iostream>


#include "IPUtils.hpp"
#include "Structures.hpp"

using pcapturepp::structures::DeviceInfo;

#ifndef AX25_P_IP
# define AX25_P_IP		0xcc	/* ARPA Internet Protocol     */
#endif

#define DEFAULT_DEVICE		NULL


#define FINAL_PACKS		2

namespace arping {
    struct Device {
        char *name;
        int ifindex;
        struct ifaddrs *ifa;
    };

struct RunState {
        struct Device device;
        char *source;
        struct ifaddrs *ifa0;
        struct in_addr gsrc;
        struct in_addr gdst;
        int gdst_family;
        char *target;
        int count;
        int timeout;
        unsigned int interval;
        int socketfd;
        struct sockaddr_storage me;
        struct sockaddr_storage he;
        struct timespec start;
        struct timespec last;
        int sent;
        int brd_sent;
        int received;
        int brd_recv;
        int req_recv;
        uid_t euid;
        unsigned int
            advert:1,
            broadcast_only:1,
            dad:1,
            quiet:1,
            quit_on_reply:1,
            unicasting:1,
            unsolicited:1;
    };

    static void limit_capabilities(struct RunState *ctl)
    {
        ctl->euid = geteuid();
    }

    static int modify_capability_raw(struct RunState *ctl, int on)
    {
        if (setuid(on ? ctl->euid : getuid()))
            error(-1, errno, "setuid");
        return 0;
    }

    static void drop_capabilities(void)
    {
        if (setuid(getuid()) < 0)
            error(-1, errno, "setuid");
    }

    static inline int enable_capability_raw(struct RunState *ctl)
    {
        return modify_capability_raw(ctl, 1);
    }

    static inline int disable_capability_raw(struct RunState *ctl)
    {
        return modify_capability_raw(ctl, 0);
    }

    static int send_pack(struct RunState *ctl)
    {
        int err;
        struct timespec now;
        unsigned char buf[256];
        struct arphdr *ah = (struct arphdr *)buf;
        unsigned char *p = (unsigned char *)(ah + 1);
        struct sockaddr_ll *ME = (struct sockaddr_ll *)&(ctl->me);
        struct sockaddr_ll *HE = (struct sockaddr_ll *)&(ctl->he);

        ah->ar_hrd = htons(ME->sll_hatype);
        if (ah->ar_hrd == htons(ARPHRD_FDDI))
            ah->ar_hrd = htons(ARPHRD_ETHER);

        /*
        * Exceptions everywhere. AX.25 uses the AX.25 PID value not the
        * DIX code for the protocol. Make these device structure fields.
        */
        if (ah->ar_hrd == htons(ARPHRD_AX25) ||
            ah->ar_hrd == htons(ARPHRD_NETROM))
            ah->ar_pro = htons(AX25_P_IP);
        else
            ah->ar_pro = htons(ETH_P_IP);

        ah->ar_hln = ME->sll_halen;
        ah->ar_pln = 4;
        ah->ar_op  = ctl->advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

        memcpy(p, &ME->sll_addr, ah->ar_hln);
        p += ME->sll_halen;

        memcpy(p, &ctl->gsrc, 4);
        p += 4;

        if (ctl->advert)
            memcpy(p, &ME->sll_addr, ah->ar_hln);
        else
            memcpy(p, &HE->sll_addr, ah->ar_hln);
        p += ah->ar_hln;

        memcpy(p, &ctl->gdst, 4);   
        p += 4;

        clock_gettime(CLOCK_MONOTONIC, &now);
        err = sendto(ctl->socketfd, buf, p - buf, 0, (struct sockaddr *)HE, sizeof(struct sockaddr_ll));
        if (err == p - buf) {
            ctl->last = now;
            ctl->sent++;
            if (!ctl->unicasting)
                ctl->brd_sent++;
        }
        return err;
    }

    static int finish(struct RunState *ctl)
    {
        if (!ctl->quiet) {
            printf(_("Sent %d probes (%d broadcast(s))\n"), ctl->sent, ctl->brd_sent);
            printf(_("Received %d response(s)"), ctl->received);
            if (ctl->brd_recv || ctl->req_recv) {
                printf(" (");
                if (ctl->req_recv)
                    printf(_("%d request(s)"), ctl->req_recv);
                if (ctl->brd_recv)
                    printf(_("%s%d broadcast(s)"),
                        ctl->req_recv ? ", " : "",
                        ctl->brd_recv);
                printf(")");
            }
            printf("\n");
            fflush(stdout);
        }

        /* arping exit code evaluation */
        if (ctl->dad)
            return !!ctl->received;

        if (ctl->unsolicited)
            return 0;

        if (ctl->timeout && ctl->count > 0 && !ctl->quit_on_reply)
            return !(ctl->count <= ctl->received);

        return !ctl->received;
    }

    static void print_hex(unsigned char *p, int len)
    {
        int i;

        for (i = 0; i < len; i++) {
            printf("%02X", p[i]);
            if (i != len - 1)
                printf(":");
        }
    }

    static int recv_pack(struct RunState *ctl, unsigned char *buf, ssize_t len,
                struct sockaddr_ll *FROM)
    {
        struct timespec ts;
        struct arphdr *ah = (struct arphdr *)buf;
        unsigned char *p = (unsigned char *)(ah + 1);
        struct in_addr src_ip, dst_ip;

        clock_gettime(CLOCK_MONOTONIC, &ts);

        /* Filter out wild packets */
        if (FROM->sll_pkttype != PACKET_HOST &&
            FROM->sll_pkttype != PACKET_BROADCAST &&
            FROM->sll_pkttype != PACKET_MULTICAST)
            return 0;

        /* Only these types are recognised */
        if (ah->ar_op != htons(ARPOP_REQUEST) &&
            ah->ar_op != htons(ARPOP_REPLY))
            return 0;

        /* ARPHRD check and this darned FDDI hack here :-( */
        if (ah->ar_hrd != htons(FROM->sll_hatype) &&
            (FROM->sll_hatype != ARPHRD_FDDI || ah->ar_hrd != htons(ARPHRD_ETHER)))
            return 0;

        /*
        * Protocol must be IP - but exceptions everywhere. AX.25 and NETROM
        * use the AX.25 PID value not the DIX code for the protocol.
        */
        if (ah->ar_hrd == htons(ARPHRD_AX25) ||
            ah->ar_hrd == htons(ARPHRD_NETROM)) {
            if (ah->ar_pro != htons(AX25_P_IP))
                return 0;
        } else if (ah->ar_pro != htons(ETH_P_IP))
            return 0;

        if (ah->ar_pln != 4)
            return 0;
        if (ah->ar_hln != ((struct sockaddr_ll *)&ctl->me)->sll_halen)
            return 0;
        if (len < (ssize_t) sizeof(*ah) + 2 * (4 + ah->ar_hln))
            return 0;
        memcpy(&src_ip, p + ah->ar_hln, 4);
        memcpy(&dst_ip, p + ah->ar_hln + 4 + ah->ar_hln, 4);
        if (!ctl->dad) {
            if (src_ip.s_addr != ctl->gdst.s_addr)
                return 0;
            if (ctl->gsrc.s_addr != dst_ip.s_addr)
                return 0;
            if (memcmp(p + ah->ar_hln + 4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln))
                return 0;
        } else {
            if (src_ip.s_addr != ctl->gdst.s_addr)
                return 0;
            if (memcmp(p, ((struct sockaddr_ll *)&ctl->me)->sll_addr,
                ((struct sockaddr_ll *)&ctl->me)->sll_halen) == 0)
                return 0;
            if (ctl->gsrc.s_addr && ctl->gsrc.s_addr != dst_ip.s_addr)
                return 0;
        }
        if (!ctl->quiet) {
            int s_printed = 0;
            printf("%s ", FROM->sll_pkttype == PACKET_HOST ? _("Unicast") : _("Broadcast"));
            printf(_("%s from "), ah->ar_op == htons(ARPOP_REPLY) ? _("reply") : _("request"));
            printf("%s [", inet_ntoa(src_ip));
            print_hex(p, ah->ar_hln);
            printf("] ");
            if (dst_ip.s_addr != ctl->gsrc.s_addr) {
                printf(_("for %s "), inet_ntoa(dst_ip));
                s_printed = 1;
            }
            if (memcmp(p + ah->ar_hln + 4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln)) {
                if (!s_printed)
                    printf(_("for "));
                printf("[");
                print_hex(p + ah->ar_hln + 4, ah->ar_hln);
                printf("]");
            }
            if (ctl->last.tv_sec) {
                long usecs = (ts.tv_sec - ctl->last.tv_sec) * 1000000 +
                    (ts.tv_nsec - ctl->last.tv_nsec + 500) / 1000;
                long msecs = (usecs + 500) / 1000;
                usecs -= msecs * 1000 - 500;
                printf(_(" %ld.%03ldms\n"), msecs, usecs);
            } else {
                printf(_(" UNSOLICITED?\n"));
            }
            fflush(stdout);
        }
        ctl->received++;
        if (ctl->timeout && (ctl->received == ctl->count))
            return FINAL_PACKS;
        if (FROM->sll_pkttype != PACKET_HOST)
            ctl->brd_recv++;
        if (ah->ar_op == htons(ARPOP_REQUEST))
            ctl->req_recv++;
        if (ctl->quit_on_reply || (ctl->count == 0 && ctl->received == ctl->sent))
            return FINAL_PACKS;
        if (!ctl->broadcast_only) {
            memcpy(((struct sockaddr_ll *)&ctl->he)->sll_addr, p,
                ((struct sockaddr_ll *)&ctl->me)->sll_halen);
            ctl->unicasting = 1;
        }
        return 1;
    }

    static int outgoing_device(struct RunState *const ctl, struct nlmsghdr *nh)
    {
        struct rtmsg *rm = (struct rtmsg *)NLMSG_DATA(nh);
        size_t len = RTM_PAYLOAD(nh);
        struct rtattr *ra;

        if (nh->nlmsg_type != RTM_NEWROUTE) {
            error(0, 0, "NETLINK new route message type");
            return 1;
        }
        for (ra = RTM_RTA(rm); RTA_OK(ra, (unsigned short)len); ra = RTA_NEXT(ra, len)) {
            if (ra->rta_type == RTA_OIF) {
                int *oif = (int *)RTA_DATA(ra);
                static char dev_name[IF_NAMESIZE];

                ctl->device.ifindex = *oif;
                if (!if_indextoname(ctl->device.ifindex, dev_name)) {
                    error(0, errno, "if_indextoname failed");
                    return 1;
                }
                ctl->device.name = dev_name;
            }
        }
        return 0;
    }

    static void netlink_query(struct RunState *const ctl, const int flags,
                const int type, void const *const arg, size_t len)
    {
        const size_t buffer_size = 4096;
        int fd;
        static uint32_t seq;
        struct msghdr mh = { 0 };
        struct sockaddr_nl sa = {.nl_family = AF_NETLINK };
        struct nlmsghdr *nh, *unmodified_nh;
        struct iovec iov;
        ssize_t msg_len;
        int ret = 1;

        mh.msg_name = (void *)&sa;
        mh.msg_namelen = sizeof(sa);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        unmodified_nh = nh = (struct nlmsghdr *)calloc(1, buffer_size);
        if (!nh)
            error(1, errno, "allocating %zu bytes failed", buffer_size);

        nh->nlmsg_len = NLMSG_LENGTH(len);
        nh->nlmsg_flags = flags;
        nh->nlmsg_type = type;
        nh->nlmsg_seq = ++seq;
        memcpy(NLMSG_DATA(nh), arg, len);

        iov.iov_base = nh;
        iov.iov_len = buffer_size;

        fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0) {
            error(0, errno, "NETLINK_ROUTE socket failed");
            goto fail;
        }
        if (sendmsg(fd, &mh, 0) < 0) {
            error(0, errno, "NETLINK_ROUTE socket failed");
            goto fail;
        }
        do {
            msg_len = recvmsg(fd, &mh, 0);
        } while (msg_len < 0 && errno == EINTR);

        for (nh = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
            if (nh->nlmsg_seq != seq)
                continue;
            switch (nh->nlmsg_type) {
            case NLMSG_ERROR:
            case NLMSG_OVERRUN:
                errno = EIO;
                error(0, 0, "NETLINK_ROUTE unexpected iov element");
                goto fail;
            case NLMSG_DONE:
                ret = 0;
                break;
            default:
                ret = outgoing_device(ctl, nh);
                break;
            }
        }
    fail:
        free(unmodified_nh);
        if (0 <= fd)
            close(fd);
        if (ret)
            exit(1);
    }

    static void guess_device(struct RunState *const ctl)
    {
        size_t addr_len, len;
        struct {
            struct rtmsg rm;
            struct rtattr ra;
            char addr[16];
        } query = { {0}, {0}, {0} };

        switch (ctl->gdst_family) {
        case AF_INET:
            addr_len = 4;
            break;
        case AF_INET6:
            addr_len = 16;
            break;
        default:
            error(1, 0, "unknown address family, please, use option -I.");
            abort();
        }

        query.rm.rtm_family = ctl->gdst_family;
        query.ra.rta_len = RTA_LENGTH(addr_len);
        query.ra.rta_type = RTA_DST;
        memcpy(RTA_DATA(&query.ra), &ctl->gdst, addr_len);
        len = NLMSG_ALIGN(sizeof(struct rtmsg)) + RTA_LENGTH(addr_len);
        netlink_query(ctl, NLM_F_REQUEST, RTM_GETROUTE, &query, len);
    }

    /* Common check for ifa->ifa_flags */
    static int check_ifflags(struct RunState const *const ctl, unsigned int ifflags)
    {
        if (!(ifflags & IFF_UP)) {
            if (ctl->device.name != NULL) {
                if (!ctl->quiet)
                    printf(_("Interface \"%s\" is down\n"), ctl->device.name);
                exit(2);
            }
            return -1;
        }
        if (ifflags & (IFF_NOARP | IFF_LOOPBACK)) {
            if (ctl->device.name != NULL) {
                if (!ctl->quiet)
                    printf(_("Interface \"%s\" is not ARPable\n"), ctl->device.name);
                exit(ctl->dad ? 0 : 2);
            }
            return -1;
        }
        return 0;
    }

    static int check_device(struct RunState *ctl)
    {
        int rc;
        struct ifaddrs *ifa;
        int n = 0;

        rc = getifaddrs(&ctl->ifa0);
        if (rc) {
            error(0, errno, "getifaddrs");
            return -1;
        }

        for (ifa = ctl->ifa0; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr)
                continue;
            if (ifa->ifa_addr->sa_family != AF_PACKET)
                continue;
            if (ctl->device.name && ifa->ifa_name && strcmp(ifa->ifa_name, ctl->device.name))
                continue;

            if (check_ifflags(ctl, ifa->ifa_flags) < 0)
                continue;

            if (!((struct sockaddr_ll *)ifa->ifa_addr)->sll_halen)
                continue;
            if (!ifa->ifa_broadaddr)
                continue;

            ctl->device.ifa = ifa;

            if (n++)
                break;
        }

        if (n == 1 && ctl->device.ifa) {
            ctl->device.ifindex = if_nametoindex(ctl->device.ifa->ifa_name);
            if (!ctl->device.ifindex) {
                error(0, errno, "if_nametoindex");
                freeifaddrs(ctl->ifa0);
                return -1;
            }
            ctl->device.name = ctl->device.ifa->ifa_name;
            return 0;
        }
        return 1;
    }

    /*
    * find_broadcast_address()
    *
    * This fills the device "broadcast address"
    * based on information found by check_device() function.
    */
    static void find_broadcast_address(struct RunState *ctl)
    {
        struct sockaddr_ll *he = (struct sockaddr_ll *)&(ctl->he);

        if (ctl->device.ifa) {
            struct sockaddr_ll *sll =
                (struct sockaddr_ll *)ctl->device.ifa->ifa_broadaddr;

            if (sll->sll_halen == he->sll_halen) {
                memcpy(he->sll_addr, sll->sll_addr, he->sll_halen);
                return;
            }
        }
        if (!ctl->quiet)
            fprintf(stderr, _("WARNING: using default broadcast address.\n"));
        memset(he->sll_addr, -1, he->sll_halen);
    }

    static int event_loop(struct RunState *ctl)
    {
        int exit_loop = 0;
        ssize_t s;
        enum {
            POLLFD_SIGNAL = 0,
            POLLFD_TIMER,
            POLLFD_TIMEOUT,
            POLLFD_SOCKET,
            POLLFD_COUNT
        };
        struct pollfd pfds[POLLFD_COUNT];

        sigset_t mask;
        int sfd;
        struct signalfd_siginfo sigval;

        int tfd;
        struct itimerspec timerfd_vals;
        timerfd_vals.it_interval.tv_sec = ctl->interval;
        timerfd_vals.it_interval.tv_nsec = 0;
        timerfd_vals.it_value.tv_sec = ctl->interval;
        timerfd_vals.it_value.tv_nsec = 0;
        int timeoutfd;
        struct itimerspec timeoutfd_vals;
        timeoutfd_vals.it_interval.tv_sec = ctl->timeout;
        timeoutfd_vals.it_interval.tv_nsec = 0;
        timeoutfd_vals.it_value.tv_sec = ctl->timeout;
        timeoutfd_vals.it_value.tv_nsec = 0;
        uint64_t exp, total_expires = 1;

        unsigned char packet[4096];
        struct sockaddr_storage from = {0};
        socklen_t addr_len = sizeof(from);

        /* signalfd */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGQUIT);
        sigaddset(&mask, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
            error(0, errno, "sigprocmask failed");
            return 1;
        }
        sfd = signalfd(-1, &mask, 0);
        if (sfd == -1) {
            error(0, errno, "signalfd");
            return 1;
        }
        pfds[POLLFD_SIGNAL].fd = sfd;
        pfds[POLLFD_SIGNAL].events = POLLIN | POLLERR | POLLHUP;

        /* interval timerfd */
        tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (tfd == -1) {
            error(0, errno, "timerfd_create failed");
            return 1;
        }
        if (timerfd_settime(tfd, 0, &timerfd_vals, NULL)) {
            error(0, errno, "timerfd_settime failed");
            return 1;
        }
        pfds[POLLFD_TIMER].fd = tfd;
        pfds[POLLFD_TIMER].events = POLLIN | POLLERR | POLLHUP;

        /* timeout timerfd */
        timeoutfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timeoutfd == -1) {
            error(0, errno, "timerfd_create failed");
            return 1;
        }
        if (timerfd_settime(timeoutfd, 0, &timeoutfd_vals, NULL)) {
            error(0, errno, "timerfd_settime failed");
            return 1;
        }
        pfds[POLLFD_TIMEOUT].fd = timeoutfd;
        pfds[POLLFD_TIMEOUT].events = POLLIN | POLLERR | POLLHUP;

        /* socket */
        pfds[POLLFD_SOCKET].fd = ctl->socketfd;
        pfds[POLLFD_SOCKET].events = POLLIN | POLLERR | POLLHUP;
        send_pack(ctl);

        while (!exit_loop) {
            int ret;
            size_t i;

            if ((ctl->sent == ctl->count) && ctl->unsolicited) {
                exit_loop = 1;
                continue;
            }

            ret = poll(pfds, POLLFD_COUNT, -1);
            if (ret <= 0) {
                if (errno == EAGAIN)
                    continue;
                if (errno)
                    error(0, errno, "poll failed");
                exit_loop = 1;
                continue;
            }

            for (i = 0; i < POLLFD_COUNT; i++) {
                if (pfds[i].revents == 0)
                    continue;
                switch (i) {
                case POLLFD_SIGNAL:
                    s = read(sfd, &sigval, sizeof(struct signalfd_siginfo));
                    if (s != sizeof(struct signalfd_siginfo)) {
                        error(0, errno, "could not read signalfd");
                        continue;
                    }
                    if (sigval.ssi_signo == SIGINT || sigval.ssi_signo == SIGQUIT ||
                        sigval.ssi_signo == SIGTERM)
                        exit_loop = 1;
                    else
                        error(0, errno, "unexpected signal: %d", sigval.ssi_signo);
                    break;
                case POLLFD_TIMER:
                    s = read(tfd, &exp, sizeof(uint64_t));
                    if (s != sizeof(uint64_t)) {
                        error(0, errno, "could not read timerfd");
                        continue;
                    }
                    total_expires += exp;
                    if (0 < ctl->count && (uint64_t)ctl->count < total_expires) {
                        exit_loop = 1;
                        continue;
                    }
                    send_pack(ctl);
                    break;
                case POLLFD_TIMEOUT:
                    exit_loop = 1;
                    break;
                case POLLFD_SOCKET:
                    if ((s =
                        recvfrom(ctl->socketfd, packet, sizeof(packet), 0,
                            (struct sockaddr *)&from, &addr_len)) < 0) {
                        error(0, errno, "recvfrom");
                        if (errno == ENETDOWN)
                            return 2;
                        continue;
                    }
                    if (recv_pack
                        (ctl, packet, s, (struct sockaddr_ll *)&from) == FINAL_PACKS)
                        exit_loop = 1;
                    break;
                default:
                    abort();
                }
            }
        }

        close(sfd);
        close(tfd);
        freeifaddrs(ctl->ifa0);

        return finish(ctl);
    }

    DeviceInfo Arping(const string& iface, const string& source, const string& target) {
        DeviceInfo dev();
        struct RunState ctl = {
            .device = { .name = DEFAULT_DEVICE },
            .count = -1,
            .interval = 1,
            0
        };

        int ch;
        atexit(close_stdout);
        limit_capabilities(&ctl);
        ctl.count = 1;
        char *interface = strdup(iface.c_str());
        char *source_ip = strdup(source.c_str());
        ctl.device.name = interface;
        ctl.source = source_ip;
        free(interface);
        free(source_ip);

        enable_capability_raw(&ctl);
        if (ctl.socketfd < 0) {
            error(2, errno, "socket");
        }

        disable_capability_raw(&ctl);

        char *target_ip = strdup(target.c_str());
        ctl.target = target_ip;
        free(target_ip);

        if (ctl.device.name && !*ctl.device.name) {
            ctl.device.name = nullptr;
        }

        if (inet_aton(ctl.target, &ctl.gdst) != 1) {
            struct addrinfo hints = {
                .ai_family = AF_INET,
                .ai_socktype = SOCK_RAW
            };

            struct addrinfo *result;
            int status;

            status = getaddrinfo(ctl.target, NULL)
        }

        
    }

}

#endif