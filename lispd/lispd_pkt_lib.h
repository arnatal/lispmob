/*
 * lispd_pkt_lib.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 *    Lorand Jakab  <ljakab@ac.upc.edu>
 *
 */

#pragma once

#include "lispd.h"

int pkt_get_mapping_record_length(lispd_locator_chain_t *locator_chain);

void *pkt_fill_eid_from_locator_chain(void *offset, lispd_locator_chain_t *loc_chain);

void *pkt_fill_eid(void *offset, lisp_addr_t *eid, lispd_iid_t iid);

void *pkt_fill_mapping_record(
    lispd_pkt_mapping_record_t              *rec,
    lispd_locator_chain_t                   *locator_chain,
    map_reply_opts                          *opts);

void *pkt_read_eid(
    void                    *offset,
    lisp_addr_t            **eid,
    int                     *eid_afi,
    lispd_iid_t             *iid);

