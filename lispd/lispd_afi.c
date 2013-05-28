/*
 * lispd_afi.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#include "lispd_afi.h"
#include "lispd_lib.h"


int pkt_process_eid_afi(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping)
{

    uint8_t                 *cur_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    uint16_t                 lisp_afi;
    packet_tuple            *tuple;
    lispd_pkt_lcaf_5tuple_t *lcaf_5tuple;


    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        memcpy(&(mapping->eid_prefix.address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
        mapping->eid_prefix.afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(mapping->eid_prefix.address.ipv6),cur_ptr,sizeof(struct in6_addr));
        mapping->eid_prefix.afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        lcaf_ptr = (lispd_pkt_lcaf_t *)cur_ptr;
        cur_ptr  = CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        
        printf("LCAF type: %d\n",lcaf_ptr->type);
        printf("LCAF 5 TUPLE: %d\n",LCAF_5_TUPLE);
        
        switch(lcaf_ptr->type) {
        case LCAF_IID:
            mapping->iid = ntohl(*(uint32_t *)cur_ptr);
            cur_ptr = CO(lcaf_ptr, sizeof(mapping->iid));
            if (!pkt_process_eid_afi (&cur_ptr, mapping))
                return (BAD);
            break;
        case LCAF_5_TUPLE:
            tuple = get_tuple_from_mapping(mapping);
            
            lcaf_5tuple = (lispd_pkt_lcaf_5tuple_t *)cur_ptr;
            tuple->src_port = ntohs(lcaf_5tuple->src_port);
            tuple->dst_port = ntohs(lcaf_5tuple->dst_port);
            tuple->protocol = ntohs(lcaf_5tuple->protocol);
            
            printf("tuple->src_port %d\n",tuple->src_port);
            printf("tuple->dst_port %d\n",tuple->dst_port);
            printf("tuple->protocol %d\n",tuple->protocol);
            
            cur_ptr = CO(cur_ptr,sizeof(lispd_pkt_lcaf_5tuple_t));
            
//             tuple->src_port = ntohs( (uint16_t)*cur_ptr);
//             printf("tuple->src_port %d\n",tuple->src_port);
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t));
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t)); // range. Not used
//             
//             tuple->dst_port = ntohs( (uint16_t)*cur_ptr);
//             printf("tuple->dst_port %d\n",tuple->dst_port);
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t));
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t)); // range. Not used
//             
//             tuple->protocol = ntohs( (uint16_t)*cur_ptr);
//             printf("tuple->dst_port %d\n",tuple->dst_port);
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t));
//             
//             cur_ptr = CO(cur_ptr,sizeof(uint16_t)); // Src and Dst ML
//             
            
            
            cur_ptr = CO(cur_ptr,sizeof(uint16_t)); // afi. Hardcoded to IPv4
            
            memcpy(&(tuple->src_addr.address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
            tuple->src_addr.afi = AF_INET;
            printf("tuple->src_addr %s\n",get_char_from_lisp_addr_t(tuple->src_addr));
            cur_ptr = CO(cur_ptr,get_addr_len(AF_INET));
            
            cur_ptr = CO(cur_ptr,sizeof(uint16_t)); // afi. Hardcoded to IPv4
            
            memcpy(&(tuple->dst_addr.address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
            tuple->dst_addr.afi = AF_INET;
            printf("tuple->dst_addr %s\n",get_char_from_lisp_addr_t(tuple->dst_addr));
            cur_ptr = CO(cur_ptr,get_addr_len(AF_INET));
            
            //We need the dst address in the mapping to for code backward compatibility
            copy_lisp_addr(&(mapping->eid_prefix),&(tuple->dst_addr));
            
            
            break;
        default:
            mapping->eid_prefix.afi = -1;
            lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown LCAF type %d in EID", lcaf_ptr->type);
            return (BAD);
        }
        break;
    case LISP_AFI_NO_EID:
        mapping->eid_prefix.afi = 0;
        break;
    default:
        mapping->eid_prefix.afi = -1;
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown AFI type %d in EID", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}

/*
 * Reads the address information from the packet and fill the lisp_addr_t
 */

int pkt_process_rloc_afi(
        uint8_t             **offset,
        lispd_locator_elt   *locator)
{
    uint8_t                  *cur_ptr;
    uint16_t                 lisp_afi;

    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        memcpy(&(locator->locator_addr->address.ip.s_addr),cur_ptr,sizeof(struct in_addr));
        locator->locator_addr->afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(locator->locator_addr->address.ipv6),cur_ptr,sizeof(struct in6_addr));
        locator->locator_addr->afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_rloc_afi: LCAF address is not supported in locators");
        return (BAD);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_rloc_afi: Unknown AFI type %d in locator", lisp_afi);
        return (BAD);
    }
    *offset = cur_ptr;
    return (GOOD);
}
