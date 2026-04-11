/*
 * DHCP Client Implementation
 *
 * Standalone DHCP client for configuring IPv4 network interfaces.
 * Translated from Rust implementation in muvm/src/guest/net.rs
 */

#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>

/* BOOTP vendor-specific area size (64) - magic cookie (4) */
#define DHCP_OPTIONS_SIZE 60

/* DHCP packet structure (RFC 2131) */
struct dhcp_packet {
    uint8_t op;     /* Message op code / message type (1 = BOOTREQUEST) */
    uint8_t htype;  /* Hardware address type (1 = Ethernet) */
    uint8_t hlen;   /* Hardware address length (6 for Ethernet) */
    uint8_t hops;   /* Client sets to zero */
    uint32_t xid;   /* Transaction ID */
    uint16_t secs;  /* Seconds elapsed since client began address acquisition */
    uint16_t flags; /* Flags (0x8000 = Broadcast) */
    uint32_t ciaddr;    /* Client IP address */
    uint32_t yiaddr;    /* 'your' (client) IP address */
    uint32_t siaddr;    /* IP address of next server to use in bootstrap */
    uint32_t giaddr;    /* Relay agent IP address */
    uint8_t chaddr[16]; /* Client hardware address */
    uint8_t sname[64];  /* Optional server host name */
    uint8_t file[128];  /* Boot file name */
    uint32_t magic;     /* Magic cookie (0x63825363) */
    uint8_t options[DHCP_OPTIONS_SIZE]; /* Options field */
} __attribute__((packed));

/*
 * Perform DHCP discovery and configuration for a network interface
 *
 * This function:
 * 1. Binds a UDP socket to the interface using SO_BINDTODEVICE
 * 2. Sends a DHCP DISCOVER message with Rapid Commit option
 * 3. Waits up to 100ms for a response:
 *    - If DHCPACK (Rapid Commit): applies configuration directly
 *    - If DHCPOFFER: sends DHCPREQUEST and waits for DHCPACK
 *    - If no response: returns success (VM may be IPv6-only)
 * 4. Parses the ACK and configures:
 *    - IPv4 address with appropriate prefix length
 *    - Default gateway route
 *    - DNS servers (overwriting /etc/resolv.conf)
 *    - Interface MTU
 *
 * Parameters:
 *   iface - The name of the network interface to be configured.
 *
 * Returns:
 *   0 on success (whether or not DHCP response was received)
 *  -1 on error
 */
int do_dhcp(const char *iface);

#endif /* DHCP_H */
