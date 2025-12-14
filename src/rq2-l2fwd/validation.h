/* SPDX-License-Identifier: BSD-3-Clause
 * Validation functions for measuring kernel security primitive overhead in DPDK
 */

#ifndef _VALIDATION_H_
#define _VALIDATION_H_

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
/* Validation modes - cumulative levels */
enum validation_mode {
    VAL_NONE = 0,           // Baseline - no validation
    VAL_IP_HEADER = 1,      // + IP header checks
    VAL_IP_CKSUM = 2,       // + IP checksum
    VAL_L4_HEADER = 3,      // + UDP/TCP header checks
    VAL_L4_CKSUM = 4,       // + UDP/TCP checksum (FULL kernel-equivalent)
};

/* Validation statistics structure */
struct validation_stats {
    uint64_t total_cycles;
    uint64_t total_packets;
    uint64_t dropped_packets;
} __rte_cache_aligned;

extern enum validation_mode __validation_mode_global;
extern struct validation_stats __validation_stats;

void validation_init(void);
void validation_reset(void);
struct validation_stats validation_get_stats(void);
void validation_set_mode(enum validation_mode mode);
enum validation_mode validation_get_mode(void);
const char* validation_mode_name(enum validation_mode mode);


/* Individual validation layer functions (exposed for testing) */
__rte_always_inline static inline int validate_ip_header(struct rte_ipv4_hdr *ip, uint16_t pkt_len){
    /* Version check */
    if ((ip->version_ihl >> 4) != 4)
        return -1;
    
    /* IHL check (minimum 5 words = 20 bytes) */
    uint8_t ihl = (ip->version_ihl & 0x0F);
    if (ihl < 5)
        return -2;
    
    /* Total length sanity check */
    uint16_t tot_len = rte_be_to_cpu_16(ip->total_length);
    if (tot_len < (ihl * 4))
        return -3;
    
    /* Check if total length fits in packet */
    if (tot_len > pkt_len - sizeof(struct rte_ether_hdr))
        return -4;
    
    return 0;
}
__rte_always_inline static inline int validate_ip_checksum(struct rte_ipv4_hdr *ip){
    uint16_t saved_cksum = ip->hdr_checksum;
    ip->hdr_checksum = 0;
    uint16_t calc_cksum = rte_ipv4_cksum(ip);
    ip->hdr_checksum = saved_cksum;
    
    return (calc_cksum == saved_cksum) ? 0 : -1;
}
__rte_always_inline static inline int validate_udp_header(struct rte_udp_hdr *udp, uint16_t udp_len){
    /* Check if UDP length is valid */
    uint16_t dgram_len = rte_be_to_cpu_16(udp->dgram_len);
    
    if (dgram_len < sizeof(struct rte_udp_hdr))
        return -1;
    
    if (dgram_len > udp_len)
        return -2;
    
    return 0;
}
__rte_always_inline static inline int validate_udp_checksum(struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp){
    if (udp->dgram_cksum == 0)
        return 0;  // UDP checksum is optional
    
    uint16_t original_cksum = udp->dgram_cksum;
    uint16_t calculated_cksum;
    
    udp->dgram_cksum = 0;
    calculated_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    udp->dgram_cksum = original_cksum;
    
    return (calculated_cksum == original_cksum) ? 0 : -1;
}
__rte_always_inline static inline int validate_tcp_header(struct rte_tcp_hdr *tcp, uint16_t tcp_len){
    /* Data offset check */
    uint8_t doff = (tcp->data_off >> 4);
    if (doff < 5 || (doff * 4) > tcp_len)
        return -1;
    
    /* Invalid flag combinations (SYN+FIN, SYN+RST) */
    uint8_t flags = tcp->tcp_flags;
    if ((flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG)) == 
        (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
        return -2;
    
    if ((flags & (RTE_TCP_SYN_FLAG | RTE_TCP_RST_FLAG)) == 
        (RTE_TCP_SYN_FLAG | RTE_TCP_RST_FLAG))
        return -3;
    
    return 0;

}
__rte_always_inline static inline int validate_tcp_checksum(struct rte_ipv4_hdr *ip, struct rte_tcp_hdr *tcp){
    uint16_t original_cksum = tcp->cksum;  // TCP uses 'cksum', not 'dgram_cksum'
    uint16_t calculated_cksum;
    
    tcp->cksum = 0;
    calculated_cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    tcp->cksum = original_cksum;
    
    return (calculated_cksum == original_cksum) ? 0 : -1;
}

// 0 for success
__rte_always_inline static inline int validate_packet(struct rte_mbuf *m)
{
    uint64_t start_tsc = rte_rdtsc();
    int result = 0;
    if (__validation_mode_global == VAL_NONE)
        goto end;
    
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    /* Only validate IPv4 packets */
    if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        
        /* Layer 1: IP Header Validation */
        if (__validation_mode_global >= VAL_IP_HEADER) {
            if (validate_ip_header(ip, m->pkt_len) < 0) {
                result = -1;
                goto end;
            }
        }
        
        /* Layer 2: IP Checksum Validation */
        if (__validation_mode_global >= VAL_IP_CKSUM) {
            if (validate_ip_checksum(ip) < 0) {
                result = -2;
                goto end;
            }
        }
        
        /* Get L4 header pointer */
        uint8_t ihl = (ip->version_ihl & 0x0F);
        void *l4_hdr = (void *)((uint8_t *)ip + (ihl * 4));
        uint16_t ip_len = rte_be_to_cpu_16(ip->total_length);
        uint16_t l4_len = ip_len - (ihl * 4);
        
        /* Layer 3 & 4: L4 Protocol-specific validation */
        if (ip->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            
            /* Layer 3: UDP Header Validation */
            if (__validation_mode_global >= VAL_L4_HEADER) {
                if (validate_udp_header(udp, l4_len) < 0) {
                    result = -3;
                    goto end;
                }
            }
            
            /* Layer 4: UDP Checksum Validation */
            if (__validation_mode_global >= VAL_L4_CKSUM) {
                if (validate_udp_checksum(ip, udp) < 0) {
                    result = -4;
                    goto end;
                }
            }
        } else if (ip->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            
            /* Layer 3: TCP Header Validation */
            if (__validation_mode_global >= VAL_L4_HEADER) {
                if (validate_tcp_header(tcp, l4_len) < 0) {
                    result = -3;
                    goto end;
                }
            }
            
            /* Layer 4: TCP Checksum Validation */
            if (__validation_mode_global >= VAL_L4_CKSUM) {
                if (validate_tcp_checksum(ip, tcp) < 0) {
                    result = -4;
                    goto end;
                }
            }
        }
    }
    
end:
    __validation_stats.total_cycles += (rte_rdtsc() - start_tsc);
    __validation_stats.total_packets++;
    if (result < 0)
        __validation_stats.dropped_packets++;
    
    return result;
}


#endif /* _VALIDATION_H_ */