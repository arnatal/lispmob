/*
 * rtr_external.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * External definitions for rtr
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Alberto Rodríguez Natal <arnatal@ac.upc.edu>
 * 
 */

#include "../lispd/lispd_external.h"
 

#define KEY_TYPE 0
#define KEY "lispmob"

#define RTR_TEST_RLOC	"192.168.56.102"
#define RTR_TEST_RLOC_AFI	AF_INET

#define PEER_ADD "192.168.56.101"


extern lisp_addr_t global_mn_rloc;
extern lisp_addr_t local_mn_rloc;
extern unsigned int global_mn_port;

extern  int rtr_process_info_nat_msg(uint8_t * packet, 
                                     int s, 
                                     struct sockaddr *from,
                                     int afi);

extern int process_info_request_msg(uint8_t * packet, 
                             int s,
                             struct sockaddr *from, 
                             int afi);

extern int process_ecm_map_register_msg(uint8_t * packet, 
                                 int s,
                                 struct sockaddr *from, 
                                 int afi);

extern int rtr_process_map_notify_msg(uint8_t * packet, 
                               int s,
                               struct sockaddr *from, 
                               int afi);


int build_and_send_data_map_notify(lispd_pkt_map_notify_t *map_notify_pkt,
                                   unsigned int map_notify_pkt_len,
                                   lisp_addr_t *inner_addr_from,
                                   lisp_addr_t *inner_addr_dest,
                                   unsigned int inner_port_from,
                                   unsigned int inner_port_dest,
                                   lisp_addr_t *outer_addr_from,
                                   lisp_addr_t *outer_addr_dest,
                                   unsigned int outer_port_from,
                                   unsigned int outer_port_dest);



lispd_pkt_info_nat_t *build_info_reply_pkt(uint64_t nonce,
                                           uint32_t ttl,
                                           uint8_t eid_mask_length,
                                           lisp_addr_t *eid_prefix,
                                           uint16_t ms_udp_port,
                                           uint16_t etr_udp_port,
                                           lisp_addr_t *global_etr_rloc,
                                           lisp_addr_t *ms_rloc,
                                           lisp_addr_t *private_etr_rloc,
                                           lisp_addr_list_t *rtr_rloc_list,
                                           uint32_t *pkt_len);

int process_map_register_msg(uint8_t * packet, int s,
                             struct sockaddr *from, int afi);


extern int build_and_send_info_reply(uint64_t nonce,
                                     uint16_t key_type,
                                     char *key,
                                     uint32_t ttl,
                                     uint8_t eid_mask_length,
                                     lisp_addr_t * eid_prefix,
                                     uint16_t ms_udp_port,
                                     uint16_t etr_udp_port,
                                     lisp_addr_t * global_etr_rloc,
                                     lisp_addr_t * ms_rloc,
                                     lisp_addr_t * private_etr_rloc,
                                     lisp_addr_list_t * rtr_rloc_list);
