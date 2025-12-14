/* SPDX-License-Identifier: BSD-3-Clause
 * Validation functions for measuring kernel security primitive overhead in DPDK
 */

#include <stdint.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "validation.h"

#define stats __validation_stats
/* Global validation state */
enum validation_mode __validation_mode_global = VAL_NONE;
struct validation_stats __validation_stats = {0};

/* Initialize validation statistics */
void 
validation_init(void)
{
    __validation_mode_global = VAL_NONE;
    stats.total_cycles = 0;
    stats.total_packets = 0;
    stats.dropped_packets = 0;
}

/* Reset validation statistics */
void 
validation_reset(void)
{
    stats.total_cycles = 0;
    stats.total_packets = 0;
    stats.dropped_packets = 0;
}

/* Get validation statistics */
struct validation_stats 
validation_get_stats(void)
{
    return stats;
}

/* Set current validation mode */
void 
validation_set_mode(enum validation_mode mode)
{
    __validation_mode_global = mode;
}

/* Get current validation mode */
enum validation_mode 
validation_get_mode(void)
{
    return __validation_mode_global;
}

/* Get validation mode name as string */
const char* 
validation_mode_name(enum validation_mode mode)
{
    switch(mode) {
        case VAL_NONE: return "NONE (Baseline)";
        case VAL_IP_HEADER: return "IP_HEADER";
        case VAL_IP_CKSUM: return "IP_CKSUM";
        case VAL_L4_HEADER: return "L4_HEADER";
        case VAL_L4_CKSUM: return "L4_CKSUM (FULL)";
        default: return "UNKNOWN";
    }
}