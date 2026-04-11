/*
 * DHCP Client Implementation
 *
 * Standalone DHCP client for configuring IPv4 network interfaces.
 * Translated from Rust implementation in muvm/src/guest/net.rs
 */

#include "dhcp.h"

#include <net/if.h>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DHCP_BUFFER_SIZE 576
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_ACK 5

/* Helper function to send netlink message */
static int nl_send(int sock, struct nlmsghdr *nlh)
{
    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
    };

    struct iovec iov = {
        .iov_base = nlh,
        .iov_len = nlh->nlmsg_len,
    };

    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    return sendmsg(sock, &msg, 0);
}

/* Helper function to receive netlink response */
static int nl_recv(int sock, char *buf, size_t len)
{
    struct sockaddr_nl sa;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len,
    };

    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    return recvmsg(sock, &msg, 0);
}

/* Add routing attribute to netlink message */
static void add_rtattr(struct nlmsghdr *nlh, int type, const void *data,
                       int len)
{
    int rtalen = RTA_SPACE(len);
    struct rtattr *rta =
        (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rtalen;
}

/* Set MTU */
static int set_mtu(int nl_sock, int iface_index, unsigned int mtu)
{
    char buf[4096];
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    struct ifinfomsg *ifi;

    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = ARPHRD_ETHER;
    ifi->ifi_index = iface_index;

    add_rtattr(nlh, IFLA_MTU, &mtu, sizeof(mtu));

    if (nl_send(nl_sock, nlh) < 0) {
        perror("nl_send failed for set_mtu");
        return -1;
    }

    /* Receive ACK */
    int len = nl_recv(nl_sock, buf, sizeof(buf));
    if (len < (int)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        perror("nl_recv failed for set_mtu");
        return -1;
    }

    if (nlh->nlmsg_type != NLMSG_ERROR) {
        printf("netlink didn't return a valid answer for set_mtu\n");
        return -1;
    }

    err = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (err->error != 0) {
        printf("netlink returned an error for set_mtu: %d\n", err->error);
        return -1;
    }

    return 0;
}

/* Add or delete IPv4 route */
static int mod_route4(int nl_sock, int iface_index, int cmd, struct in_addr gw)
{
    char buf[4096];
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    struct rtmsg *rtm;
    struct in_addr dst = {.s_addr = INADDR_ANY};

    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = cmd;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = 0;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_flags = 0;

    add_rtattr(nlh, RTA_OIF, &iface_index, sizeof(iface_index));
    add_rtattr(nlh, RTA_DST, &dst, sizeof(dst));
    add_rtattr(nlh, RTA_GATEWAY, &gw, sizeof(gw));

    if (nl_send(nl_sock, nlh) < 0) {
        perror("nl_send failed for mod_route4");
        return -1;
    }

    /* Receive ACK */
    int len = nl_recv(nl_sock, buf, sizeof(buf));
    if (len < (int)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        perror("nl_recv failed for mod_route4");
        return -1;
    }

    if (nlh->nlmsg_type != NLMSG_ERROR) {
        printf("netlink didn't return a valid answer for mod_route4\n");
        return -1;
    }

    err = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (err->error != 0) {
        printf("netlink returned an error for mod_route4: %d\n", err->error);
        return -1;
    }

    return 0;
}

/* Add or delete IPv4 address */
static int mod_addr4(int nl_sock, int iface_index, int cmd, struct in_addr addr,
                     unsigned char prefix_len)
{
    char buf[4096];
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    struct ifaddrmsg *ifa;

    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = cmd;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix_len;
    ifa->ifa_flags = 0;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_index = iface_index;

    add_rtattr(nlh, IFA_LOCAL, &addr, sizeof(addr));
    add_rtattr(nlh, IFA_ADDRESS, &addr, sizeof(addr));

    if (nl_send(nl_sock, nlh) < 0) {
        perror("nl_send failed for mod_addr4");
        return -1;
    }

    /* Receive ACK */
    int len = nl_recv(nl_sock, buf, sizeof(buf));
    if (len < (int)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        perror("nl_recv failed for mod_addr4");
        return -1;
    }

    if (nlh->nlmsg_type != NLMSG_ERROR) {
        printf("netlink didn't return a valid answer for mod_addr4\n");
        return -1;
    }

    err = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (err->error != 0) {
        printf("netlink returned an error for mod_addr4: %d\n", err->error);
        return -1;
    }

    return 0;
}

/* Count leading ones in a 32-bit value */
static unsigned char count_leading_ones(uint32_t val)
{
    unsigned char count = 0;
    for (int i = 31; i >= 0; i--) {
        if (val & (1U << i)) {
            count++;
        } else {
            break;
        }
    }
    return count;
}

/* Return the DHCP message type (option 53) from a response, or 0 */
static unsigned char get_dhcp_msg_type(const unsigned char *response,
                                       ssize_t len)
{
    /* Walk DHCP options (TLV chain starting after the magic cookie) */
    size_t p = 240;
    while (p < (size_t)len) {
        unsigned char opt = response[p];

        if (opt == 0xff) /* end */
            break;
        if (opt == 0) { /* padding */
            p++;
            continue;
        }

        if (p + 1 >= (size_t)len)
            break;

        unsigned char opt_len = response[p + 1];
        p += 2;

        if (p + opt_len > (size_t)len)
            break;
        if (opt == 53 && opt_len >= 1) /* Message Type */
            return response[p];

        p += opt_len;
    }
    return 0;
}

/* Parse a DHCP ACK and configure the interface. Returns 0 or -1 on error. */
static int handle_dhcp_ack(int nl_sock, int iface_index,
                           const unsigned char *response, ssize_t len)
{
    FILE *resolv = NULL;
    bool tried_opening_resolv = false;

    /* Need at least 240 bytes (DHCP header + magic cookie) + 1 for options */
    if (len < 241) {
        printf("DHCPACK too short (%zd bytes)\n", len);
        return -1;
    }

    /* Parse DHCP response */
    struct in_addr addr;
    /* yiaddr is at offset 16-19 in network byte order */
    memcpy(&addr.s_addr, &response[16], sizeof(addr.s_addr));

    if (addr.s_addr == INADDR_ANY) {
        printf("DHCPACK has no address (yiaddr is 0.0.0.0)\n");
        return -1;
    }

    struct in_addr netmask = {.s_addr = INADDR_ANY};
    struct in_addr router = {.s_addr = INADDR_ANY};
    /* Clamp MTU to passt's limit */
    uint16_t mtu = 65520;

    /* Parse DHCP options (start at offset 240 after magic cookie) */
    size_t p = 240;
    while (p < (size_t)len) {
        unsigned char opt = response[p];

        if (opt == 0xff) {
            /* Option 255: End (of options) */
            break;
        }

        if (opt == 0) { /* Padding */
            p++;
            continue;
        }

        if (p + 1 >= (size_t)len)
            break;

        unsigned char opt_len = response[p + 1];
        p += 2; /* Length doesn't include code and length field itself */

        if (p + opt_len > (size_t)len) {
            /* Malformed packet, option length exceeds packet boundary */
            break;
        }

        if (opt == 1 && opt_len >= 4) {
            /* Option 1: Subnet Mask */
            memcpy(&netmask.s_addr, &response[p], sizeof(netmask.s_addr));
        } else if (opt == 3 && opt_len >= 4) {
            /* Option 3: Router */
            memcpy(&router.s_addr, &response[p], sizeof(router.s_addr));
        } else if (opt == 6 && opt_len >= 4) {
            /* Option 6: Domain Name Server */
            if (!resolv && !tried_opening_resolv) {
                tried_opening_resolv = true;
                resolv = fopen("/etc/resolv.conf", "w");
                if (!resolv) {
                    perror("Failed to open /etc/resolv.conf");
                }
            }

            if (resolv) {
                for (int dns_p = p; dns_p + 4 <= p + opt_len; dns_p += 4) {
                    fprintf(resolv, "nameserver %d.%d.%d.%d\n", response[dns_p],
                            response[dns_p + 1], response[dns_p + 2],
                            response[dns_p + 3]);
                }
            }
        } else if (opt == 26 && opt_len >= 2) {
            /* Option 26: Interface MTU */
            mtu = (response[p] << 8) | response[p + 1];

            /* We don't know yet if IPv6 is available: don't go below 1280 B
             */
            if (mtu < 1280)
                mtu = 1280;
            if (mtu > 65520)
                mtu = 65520;
        }

        p += opt_len;
    }

    if (resolv) {
        fclose(resolv);
    }

    /* Calculate prefix length from netmask */
    unsigned char prefix_len = count_leading_ones(ntohl(netmask.s_addr));

    if (mod_addr4(nl_sock, iface_index, RTM_NEWADDR, addr, prefix_len) != 0) {
        printf("couldn't add the address provided by the DHCP server\n");
        return -1;
    }
    if (mod_route4(nl_sock, iface_index, RTM_NEWROUTE, router) != 0) {
        printf("couldn't add the default route provided by the DHCP server\n");
        return -1;
    }
    set_mtu(nl_sock, iface_index, mtu);
    return 0;
}

/* Send DISCOVER with Rapid Commit, process ACK, configure address and route */
int do_dhcp(const char *iface)
{
    struct sockaddr_in bind_addr, dest_addr;
    struct dhcp_packet request = {0};
    unsigned char response[DHCP_BUFFER_SIZE];
    struct timeval timeout;
    int iface_index;
    int broadcast = 1;
    int nl_sock = -1;
    int sock = -1;
    int ret = -1;

    iface_index = if_nametoindex(iface);
    if (iface_index == 0) {
        perror("Failed to find index for network interface");
        return ret;
    }

    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock < 0) {
        perror("Failed to create netlink socket");
        return ret;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
        .nl_groups = 0,
    };

    if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Failed to bind netlink socket");
        goto cleanup;
    }

    /* Send request (DHCPDISCOVER) */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket failed");
        goto cleanup;
    }

    /* Allow broadcast */
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) < 0) {
        perror("setsockopt SO_BROADCAST failed");
        goto cleanup;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface,
                   strlen(iface) + 1) < 0) {
        perror("setsockopt SO_BINDTODEVICE failed");
        goto cleanup;
    }

    /* Bind to port 68 (DHCP client) */
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(68);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind failed");
        goto cleanup;
    }

    request.op = 1;    /* BOOTREQUEST */
    request.htype = 1; /* Hardware address type: Ethernet */
    request.hlen = 6;  /* Hardware address length */
    request.hops = 0;  /* DHCP relay Hops */
    request.xid =
        htonl(getpid()); /* Transaction ID: use PID for some randomness */
    request.secs =
        0; /* Seconds elapsed since beginning of acquisition or renewal */
    request.flags = htons(0x8000); /* DHCP message flags: Broadcast */
    request.ciaddr = 0;            /* Client IP address (not set yet) */
    request.yiaddr = 0;            /* 'your' IP address (server will fill) */
    request.siaddr = 0;            /* Server IP address (not set) */
    request.giaddr = 0;            /* Relay agent IP address (not set) */
    request.magic = htonl(0x63825363); /* Magic cookie */

    /* Populate chaddr with the interface's MAC address */
    struct ifreq mac_ifr;
    memset(&mac_ifr, 0, sizeof(mac_ifr));
    strncpy(mac_ifr.ifr_name, iface, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &mac_ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR) failed");
        goto cleanup;
    }
    memcpy(request.chaddr, mac_ifr.ifr_hwaddr.sa_data, 6);

    /* Build DHCP options */
    int opt_offset = 0;

    /* Option 53: DHCP Message Type = DISCOVER (1) */
    request.options[opt_offset++] = 53;
    request.options[opt_offset++] = 1;
    request.options[opt_offset++] = 1;

    /* Option 80: Rapid Commit (RFC 4039) */
    request.options[opt_offset++] = 80;
    request.options[opt_offset++] = 0;

    /* Option 255: End of options */
    request.options[opt_offset++] = 0xff;

    /* Remaining bytes are padding (up to 300 bytes) */

    /* Send DHCP DISCOVER */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(67);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    if (sendto(sock, &request, sizeof(request), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto failed");
        goto cleanup;
    }

    /* Keep IPv6-only fast: set receive timeout to 100ms */
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
        0) {
        perror("setsockopt SO_RCVTIMEO failed");
        goto cleanup;
    }

    /* Get response: DHCPACK (Rapid Commit) or DHCPOFFER */
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t len = recvfrom(sock, response, sizeof(response), 0,
                           (struct sockaddr *)&from_addr, &from_len);

    if (len <= 0)
        goto done; /* No DHCP response — not an error, VM may be IPv6-only */

    unsigned char msg_type = get_dhcp_msg_type(response, len);

    if (msg_type == DHCP_MSG_ACK) {
        /* Rapid Commit — server sent ACK directly */
        close(sock);
        sock = -1;
        if (handle_dhcp_ack(nl_sock, iface_index, response, len) != 0)
            goto cleanup;
    } else if (msg_type == DHCP_MSG_OFFER) {
        /*
         * DHCPOFFER — complete the 4-way handshake by sending DHCPREQUEST
         * and waiting for DHCPACK. Servers without Rapid Commit (e.g.
         * gvproxy) require this.
         */
        struct in_addr offered_addr;
        memcpy(&offered_addr.s_addr, &response[16],
               sizeof(offered_addr.s_addr));

        /* Build DHCPREQUEST */
        memset(request.options, 0, sizeof(request.options));
        opt_offset = 0;

        /* Option 53: DHCP Message Type = REQUEST (3) */
        request.options[opt_offset++] = 53;
        request.options[opt_offset++] = 1;
        request.options[opt_offset++] = 3;

        /* Option 50: Requested IP Address */
        request.options[opt_offset++] = 50;
        request.options[opt_offset++] = 4;
        memcpy(&request.options[opt_offset], &offered_addr.s_addr, 4);
        opt_offset += 4;

        /* Option 54: Server Identifier (from_addr) */
        request.options[opt_offset++] = 54;
        request.options[opt_offset++] = 4;
        memcpy(&request.options[opt_offset], &from_addr.sin_addr.s_addr, 4);
        opt_offset += 4;

        /* Option 255: End */
        request.options[opt_offset++] = 0xff;

        if (sendto(sock, &request, sizeof(request), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto DHCPREQUEST failed");
            goto cleanup;
        }

        from_len = sizeof(from_addr);
        len = recvfrom(sock, response, sizeof(response), 0,
                       (struct sockaddr *)&from_addr, &from_len);

        close(sock);
        sock = -1;

        if (len <= 0) {
            printf("no DHCPACK received\n");
            goto cleanup;
        }

        if (get_dhcp_msg_type(response, len) != DHCP_MSG_ACK) {
            printf("expected DHCPACK but got message type %d\n",
                   get_dhcp_msg_type(response, len));
            goto cleanup;
        }

        if (handle_dhcp_ack(nl_sock, iface_index, response, len) != 0)
            goto cleanup;
    } else {
        printf("unexpected DHCP message type %d\n", msg_type);
        goto cleanup;
    }

done:
    ret = 0;
cleanup:
    if (sock >= 0) {
        close(sock);
    }
    if (nl_sock >= 0) {
        close(nl_sock);
    }
    return ret;
}
