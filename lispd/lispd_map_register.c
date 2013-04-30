/* 
 * lispd_map_register.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"
#include "patricia/patricia.h"

#include "lispd_nat_lib.h"


lispd_pkt_map_register_t *build_map_register_pkt(
        lispd_mapping_elt       *mapping,
        int                     *mrp_len);
int send_map_register(
        lisp_addr_t                 *ms_address,
        lispd_pkt_map_register_t    *mrp,
        int                         mrp_len);


/*
 *  map_server_register (tree)
 *
 */

timer *map_register_timer = NULL;

/*
 * Timer and arg parameters are not used but must be defined to be consistent
 * with timer call back function.
 */
int map_register(
        timer   *t,
        void    *arg)
{
    patricia_tree_t           *dbs[2];
    patricia_tree_t           *tree = NULL;
    lispd_map_server_list_t   *ms;
    lispd_pkt_map_register_t  *map_register_pkt; 
    patricia_node_t           *node;
    lispd_mapping_elt         *mapping_elt;
    int                       mrp_len = 0;
    int                       ctr = 0;
    int                       sent_map_registers = 0;
    uint32_t                  md_len;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);

    if (!map_servers) {
        lispd_log_msg(LISP_LOG_CRIT, "map_register: No Map Servers conifgured!");
        exit(EXIT_FAILURE);
    }

    for (ctr = 0 ; ctr < 2 ; ctr++) {
        tree = dbs[ctr];
        if (!tree)
            continue;
        PATRICIA_WALK(tree->head, node) {
            mapping_elt = ((lispd_mapping_elt *)(node->data));
            
            /* Quick NAT traversal port */
            if((mapping_elt)&&(nat_aware==TRUE)){
                
                if(behind_nat == UNKNOWN){
                    nat_info_request();
                }
                
                if(behind_nat==TRUE){
                    build_and_send_ecm_map_register(mapping_elt,
                                    map_servers->proxy_reply,
                                    default_ctrl_iface_v4->ipv4_address,
                                    map_servers->address,
                                    LISP_CONTROL_PORT,
                                    LISP_CONTROL_PORT,
                                    default_ctrl_iface_v4->ipv4_address,
                                    &(natt_rtr),
                                    LISP_DATA_PORT,
                                    LISP_CONTROL_PORT,
                                    map_servers->key_type,
                                    map_servers->key);
                }
      
            }else{
                if ((mapping_elt)&&((nat_aware==FALSE)||(behind_nat==FALSE))) {
                    if ((map_register_pkt =
                            build_map_register_pkt(mapping_elt, &mrp_len)) == NULL) {
                        lispd_log_msg(LISP_LOG_DEBUG_1, "map_register: Couldn't build map register packet");
                        return(BAD);
                    }

                    //  for each map server, send a register, and if verify
                    //  send a map-request for our eid prefix

                    ms = map_servers;

                    while (ms) {

                        /*
                        * Fill in proxy_reply and compute the HMAC with SHA-1.
                        */

                        map_register_pkt->proxy_reply = ms->proxy_reply;
                        memset(map_register_pkt->auth_data,0,LISP_SHA1_AUTH_DATA_LEN);   /* make sure */

                        if (!HMAC((const EVP_MD *) EVP_sha1(),
                                (const void *) ms->key,
                                strlen(ms->key),
                                (uchar *) map_register_pkt,
                                mrp_len,
                                (uchar *) map_register_pkt->auth_data,
                                &md_len)) {
                            lispd_log_msg(LISP_LOG_DEBUG_1, "HMAC failed for map-register");
                            return(BAD);
                        }

                        /* Send the map register */

                        if ((err = send_map_register(ms->address,map_register_pkt,mrp_len)) == GOOD) {
                            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent map register for %s/%d to maps server %s",
                                                        get_char_from_lisp_addr_t(mapping_elt->eid_prefix),
                                                        mapping_elt->eid_prefix_length,
                                                        get_char_from_lisp_addr_t(*(ms->address)));
                            sent_map_registers++;
                        }else {
                            lispd_log_msg(LISP_LOG_WARNING, "Couldn't send map-register for %s",get_char_from_lisp_addr_t(mapping_elt->eid_prefix));
                        }
                        ms = ms->next;
                    }
                    free(map_register_pkt);

                    if (sent_map_registers == 0){
                        lispd_log_msg(LISP_LOG_CRIT, "Couldn't register %s. \n Exiting ...",get_char_from_lisp_addr_t(mapping_elt->eid_prefix));
                        exit(EXIT_FAILURE);
                    }
                    sent_map_registers = 0;
                }
            }
        } PATRICIA_WALK_END;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (!map_register_timer) {
        map_register_timer = create_timer("Map register");
    }
    start_timer(map_register_timer, MAP_REGISTER_INTERVAL, map_register, NULL);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed map register for %s/%d in %d seconds",
                                get_char_from_lisp_addr_t(mapping_elt->eid_prefix),
                                mapping_elt->eid_prefix_length,
                                MAP_REGISTER_INTERVAL);
    return(GOOD);
}


/*
 *  build_map_register_pkt
 *
 *  Build the map-register
 *
 */

lispd_pkt_map_register_t *build_map_register_pkt(
        lispd_mapping_elt       *mapping,
        int                     *mrp_len)
{
    lispd_pkt_map_register_t *mrp;
    lispd_pkt_mapping_record_t *mr;

    *mrp_len = sizeof(lispd_pkt_map_register_t) +
              pkt_get_mapping_record_length(mapping);

    if ((mrp = malloc(*mrp_len)) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "build_map_register_pkt: Unable to allocate memory for Map Register packet: %s", strerror(errno));
        return(NULL);
    }
    memset(mrp, 0, *mrp_len);

    /*
     *  build the packet
     *
     *  Fill in mrp->proxy_reply and compute the HMAC in 
     *  send_map_register()
     *
     */

    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->map_notify       = 1;              /* TODO conf item */
    mrp->nonce            = 0;
    mrp->record_count     = 1;				/* XXX Just supported one record per map register */
    mrp->key_id           = htons(1);       /* XXX not sure */
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);


    /* skip over the fixed part,  assume one record (mr) */

    mr = (lispd_pkt_mapping_record_t *) CO(mrp, sizeof(lispd_pkt_map_register_t));

    if (pkt_fill_mapping_record(mr, mapping, NULL)) {
        return(mrp);
    } else {
        free(mrp);
        return(NULL);
    }
}


/*
 *  send_map_register
 */

int send_map_register(
        lisp_addr_t                 *ms_address,
        lispd_pkt_map_register_t    *mrp,
        int                         mrp_len)
{
    int result;
    if (ms_address->afi == AF_INET){
        if (default_ctrl_iface_v4 != NULL){
            result = send_udp_ipv4_packet(default_ctrl_iface_v4->ipv4_address,ms_address,0,LISP_CONTROL_PORT,(void *)mrp,mrp_len);
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"send_map_register: No local RLOC compatible with the afi of the Map Server %s",
                    get_char_from_lisp_addr_t(*ms_address));
            result = BAD;
        }
    }else{
        if (default_ctrl_iface_v6 != NULL){
            result = send_udp_ipv6_packet(default_ctrl_iface_v6->ipv6_address,ms_address,0,LISP_CONTROL_PORT,(void *)mrp,mrp_len);
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"send_map_register: No local RLOC compatible with the afi of the Map Server %s",
                    get_char_from_lisp_addr_t(*ms_address));
            result = BAD;
        }
    }
    return result;
}


#ifdef LISPMOBMH
/* Machinery to handle rate limited smrs when interfaces go up and down
 * in dynamic multihomed scenarios.
 */

void start_smr_timeout(void)
{
    struct itimerspec interval;

    if (timerfd_gettime(smr_timer_fd, &interval) == -1)
            lispd_log_msg(LOG_INFO, "timerfd_gettime: %s", strerror(errno));

    if (interval.it_value.tv_sec == 0){
    	/*Timer is disarmed. Start it*/

    	interval.it_interval.tv_sec  = 0;
    	interval.it_interval.tv_nsec = 0;
    	interval.it_value.tv_sec     = DEFAULT_SMR_TIMEOUT;
    	interval.it_value.tv_nsec    = 0;

    	lispd_log_msg(LOG_INFO, "Start timer to send an smr in %d seconds",
    			DEFAULT_SMR_TIMEOUT);

    	if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
    		lispd_log_msg(LOG_INFO, "timerfd_settime: %s", strerror(errno));
    }
}


void stop_smr_timeout(void)
{
    struct itimerspec interval;

    interval.it_interval.tv_sec  = 0;
    interval.it_interval.tv_nsec = 0;
    interval.it_value.tv_sec     = 0;
    interval.it_value.tv_nsec    = 0;

    lispd_log_msg(LOG_INFO, "Clear timer to send smrs");

    if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
        lispd_log_msg(LOG_INFO, "timerfd_settime: %s", strerror(errno));
}


inline void smr_on_timeout(void)
{
    ssize_t s;
    uint64_t num_exp;

    if((s = read(smr_timer_fd, &num_exp, sizeof(num_exp))) != sizeof(num_exp))
        lispd_log_msg(LOG_INFO, "read error (smr_on_timeout): %s", strerror(errno));
    /*
     * Trigger SMR to PITRs and the MN's peers
     */
    init_smr();
}
#endif





/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
