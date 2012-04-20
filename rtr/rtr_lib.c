/*
 * rtr_lib.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Various library routines.
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
 *    Alberto Rodríguez Natal    <arnatal@ac.upc.edu>
 *
 */

#include "rtr_external.h"

/*
 *  process Info-Request Message
 *  Receive a Info-Request message and process based on control bits
 *
 */

int rtr_process_info_nat_msg(uint8_t * packet, int s, struct sockaddr *from,
                         int afi)
{
    lispd_pkt_info_nat_t *nat_pkt;

    nat_pkt = (lispd_pkt_info_nat_t *) packet;

    switch (nat_pkt->rbit) {
    case NAT_NO_REPLY:
        return (process_info_request_msg(packet, s, from, afi));

    case NAT_REPLY:
		syslog(LOG_DAEMON, "process_info_nat_msg: rbit value not supported");
        return (ERROR);
        //return (process_info_reply_msg(packet, s, from, afi));

    default:
        return (ERROR);         // We should never reach here
    }
}

int build_and_send_data_map_notify(map_notify_pkt,
                                   map_notify_pkt_len,
                                   inner_addr_from,
                                   inner_addr_dest,
                                   inner_port_from,
                                   inner_port_dest,
                                   outer_addr_from,
                                   outer_addr_dest,
                                   outer_port_from, 
                                   outer_port_dest)
lispd_pkt_map_notify_t *map_notify_pkt;
unsigned int map_notify_pkt_len;
lisp_addr_t *inner_addr_from;
lisp_addr_t *inner_addr_dest;
unsigned int inner_port_from;
unsigned int inner_port_dest;
lisp_addr_t *outer_addr_from;
lisp_addr_t *outer_addr_dest;
unsigned int outer_port_from;
unsigned int outer_port_dest;
{
   

    uint8_t *data_map_notify;

    unsigned int data_map_notify_len;

    data_map_notify = build_data_encap_pkt((uint8_t *) map_notify_pkt,
                                           map_notify_pkt_len,
                                           inner_addr_from,
                                           inner_addr_dest,
                                           inner_port_from,
                                           inner_port_dest,
                                           &data_map_notify_len);

	/* XXX TODO check why this free produces a error*/
    //free(map_notify_pkt);


    if (data_map_notify == NULL) {
        return (ERROR);
    }


    if (ERROR == send_packet(data_map_notify,
                             data_map_notify_len,
                             outer_addr_from,
                             outer_port_from,
                             outer_addr_dest, outer_port_dest)) {
        free(data_map_notify);
        return (ERROR);
    }


    free(data_map_notify);

    return (NO_ERROR);
}

 
/*
 *  process Info-Request Message
 *  Receive a Info-Request message and process based on control bits
 *
 */

int process_info_request_msg(uint8_t * packet, int s,
                             struct sockaddr *from, int afi)
{

    //lispd_pkt_info_nat_t *irp;
    //lispd_pkt_info_nat_eid_t *irp_eid;
    //lispd_pkt_info_request_lcaf_t *irp_lcaf;


    //uint16_t from_afi_inet;
    uint16_t from_port;


    uint8_t lisp_type;
    uint8_t reply;

    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t auth_data[LISP_SHA1_AUTH_DATA_LEN];


    uint32_t ttl;
    uint8_t eid_mask_len;

    //uint16_t eid_prefix_afi;
    //uint16_t eid_prefix_afi_inet;

    //uint16_t lcaf_afi;
    //uint8_t flags;
    //uint8_t lcaf_type;

    lisp_addr_t eid_prefix;


    //char *eid_name;
    //char *from_addr_name;

    //lisp_addr_t *eid_addr;

    unsigned int hdr_len;

    //lispd_map_server_list_t map_server;
    //lispd_addr_t aux_addr;

    lisp_addr_t global_etr_rloc;
    lisp_addr_t ms_rloc;
    lisp_addr_t private_etr_rloc;
    lisp_addr_list_t rtr_rloc_list;
    lisp_addr_t rtr_rloc;


    printf("## PROCESING INFO REQUEST ##\n");

    /* 
     * Get source port and address. 
     * IPv4 and IPv6 support
     */
 

    //irp = (lispd_pkt_info_nat_t *) packet;

    
    hdr_len = extract_info_nat_header((lispd_pkt_info_nat_t *) packet,
                                      &lisp_type,
                                      &reply,
                                      &nonce,
                                      &key_id,
                                      &auth_data_len,
                                      (uint8_t **) & auth_data,
                                      &ttl, &eid_mask_len, &eid_prefix);


    //lisp_type=irp->lisp_type;



    //irp_eid = (lispd_pkt_info_nat_eid_t *)CO(irp, sizeof(lispd_pkt_info_nat_t));


    //ttl=ntohl(irp_eid->ttl);

    //printf("reply: %d\n", reply);

    //printf("ttl %d\n", ttl);

    //print_address(&eid_prefix);

    //eid_prefix_afi_inet=eid_prefix->afi;

    //printf("AF_INET6 %d\n", AF_INET6);


    //eid_ptr = CO(irp_eid, sizeof(lispd_pkt_info_nat_eid_t));

    //print_address(eid_prefix);

    //printf("eid_prefix_afi_from_lisp_addr %d\n",eid_prefix->afi);

    //irp_lcaf = (lispd_pkt_info_request_lcaf_t *) CO(irp, hdr_len + get_addr_len(eid_prefix.afi));

    //lcaf_afi = ntohs(irp_lcaf->lcaf_afi);

    //printf("lcaf afi %d\n", lcaf_afi);

    //lcaf_type = irp_lcaf->lcaf_type;

    //printf("lcaf type %d\n", lcaf_type);



    if (get_source_address_and_port(from, &global_etr_rloc, &from_port) == ERROR) {
        syslog(LOG_DAEMON, "process_info_request. Error retrieving source address and port");
        return (ERROR);
    }

    //print_address(&global_etr_rloc);

    ms_rloc = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);
    private_etr_rloc = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);

    rtr_rloc = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);


    printf("RTR_RLOC\n");
    print_address(&rtr_rloc);

    rtr_rloc_list.address = &rtr_rloc;
    rtr_rloc_list.next = NULL;

    // Not real map_server. Just to take advantage of existing structures. TODO update
    //aux_addr.address = global_etr_rloc;
    //map_server.address = &aux_addr;
    //map_server.key = KEY;

    printf(RTR_TEST_RLOC);
    printf("\n");

    build_and_send_info_reply(nonce,
                              KEY_TYPE,
                              KEY,
                              DEFAULT_INFO_REPLY_TIMEOUT,
                              eid_mask_len,
                              &eid_prefix,
                              LISP_CONTROL_PORT,
                              from_port,
                              &global_etr_rloc,
                              &ms_rloc, 
                              &private_etr_rloc, 
                              &rtr_rloc_list);


    return (NO_ERROR);
}




/*
 *  build_info_reply_pkt
 *
 *  Build the info-reply
 *
 */

//Suppouse at least one RTR

lispd_pkt_info_nat_t *build_info_reply_pkt(nonce,
                                           ttl,
                                           eid_mask_length,
                                           eid_prefix,
                                           ms_udp_port,
                                           etr_udp_port,
                                           global_etr_rloc,
                                           ms_rloc,
                                           private_etr_rloc,
                                           rtr_rloc_list, pkt_len)
uint64_t nonce;
uint32_t ttl;
uint8_t eid_mask_length;
lisp_addr_t *eid_prefix;
uint16_t ms_udp_port;
uint16_t etr_udp_port;
lisp_addr_t *global_etr_rloc;
lisp_addr_t *ms_rloc;
lisp_addr_t *private_etr_rloc;
lisp_addr_list_t *rtr_rloc_list;
uint32_t *pkt_len;
{
    lispd_pkt_info_nat_t *irp;
    lispd_pkt_info_reply_lcaf_t *irp_lcaf;
    unsigned int irp_len = 0;
    unsigned int header_len = 0;
    unsigned int lcaf_hdr_len = 0;
    //unsigned int lcaf_nat_len = 0;

    //unsigned short global_etr_rloc_length;
    //unsigned short ms_rloc_length;
    //unsigned short private_etr_rloc_length;
    //unsigned short rtr_rloc_length;

    unsigned int lcaf_adds_len = 0;
    lisp_addr_list_t *rtr_rloc_itr;

    void *ptr;

    irp = create_and_fill_info_nat_header(LISP_INFO_NAT,
                                          NAT_REPLY,
                                          nonce,
                                          LISP_SHA1_AUTH_DATA_LEN,
                                          ttl,
                                          eid_mask_length,
                                          eid_prefix, &header_len);


    if (irp == NULL) {
        syslog(LOG_DAEMON, "Error building info-request header");
        return (NULL);
    }


    lcaf_hdr_len = sizeof(lispd_pkt_info_reply_lcaf_t);


    // NAT lcaf addresses total length

    lcaf_adds_len = get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN  // 2 is the length of the AFI field
        + get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN
        + get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN;

    rtr_rloc_itr = rtr_rloc_list;

    while (rtr_rloc_itr != NULL) {

        lcaf_adds_len += get_addr_len(rtr_rloc_itr->address->afi) + FIELD_AFI_LEN;
        rtr_rloc_itr = rtr_rloc_itr->next;

    }


    // Total length of the packet

    irp_len = header_len + lcaf_hdr_len + lcaf_adds_len;

    // Expand the amount of memory assigned to the packet
    irp = realloc(irp, irp_len);

    if (irp == NULL) {
        syslog(LOG_DAEMON, "realloc (post-header info-nat packet): %s",
               strerror(errno));
        return (NULL);
    }


    /*
     * skip over the fixed part and build the lcaf  
     */

    irp_lcaf = (lispd_pkt_info_reply_lcaf_t *) CO(irp, header_len);

    /*
     *  make sure this is clean
     */

    memset(irp_lcaf, 0, lcaf_hdr_len + lcaf_adds_len);

    // fill lcaf info-request fields
    irp_lcaf->lcaf_afi = htons(LISP_AFI_LCAF);
    irp_lcaf->flags = 0;
    irp_lcaf->lcaf_type = LISP_LCAF_NAT;
    irp_lcaf->length = htons(lcaf_adds_len + 2 * FIELD_PORT_LEN);       // 4 is the length of the two ports fields
    irp_lcaf->ms_udp_port = htons(ms_udp_port);
    irp_lcaf->etr_udp_port = htons(etr_udp_port);


    ptr = (void *) CO(irp_lcaf, sizeof(lispd_pkt_info_reply_lcaf_t));

    // Copy the Global ETR RLOC
    if (fill_afi_and_address_fields(ptr, global_etr_rloc) == ERROR) {
        syslog(LOG_DAEMON, "Info-Reply: Error coping Global ETR RLOC");
        free(irp);
        return (NULL);
    }

    ptr = CO(ptr, get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN);

    // Copy the MS RLOC
    if (fill_afi_and_address_fields(ptr, ms_rloc) == ERROR) {
        syslog(LOG_DAEMON, "Info-Reply: Error coping MS RLOC");
        free(irp);
        return (NULL);
    }

    ptr = CO(ptr, get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN);


    // Copy the Private ETR RLOC
    if (fill_afi_and_address_fields(ptr, private_etr_rloc) == ERROR) {
        syslog(LOG_DAEMON, "Info-Reply: Error coping Private ETR RLOC");
        free(irp);
        return (NULL);
    }
 
    ptr = CO(ptr, get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN);


    // Itererate through the RTR locators and copy them
    rtr_rloc_itr = rtr_rloc_list;

    while (rtr_rloc_itr != NULL) {

        if (fill_afi_and_address_fields(ptr, rtr_rloc_itr->address) ==
            ERROR) {
            syslog(LOG_DAEMON, "Info-Reply: Error coping RTR ETR RLOC");
            free(irp);
            return (NULL);
        }

        ptr = CO(ptr, get_addr_len(rtr_rloc_itr->address->afi) + FIELD_AFI_LEN);

        rtr_rloc_itr = rtr_rloc_itr->next;

    }



    // Return the len of the packet
    *pkt_len = irp_len;

    return (irp);
}






int build_and_send_info_reply(nonce,
                              key_type,
                              key,
                              ttl,
                              eid_mask_length,
                              eid_prefix,
                              ms_udp_port,
                              etr_udp_port,
                              global_etr_rloc,
                              ms_rloc, private_etr_rloc, rtr_rloc_list)
uint64_t nonce;
uint16_t key_type;
char *key;
uint32_t ttl;
uint8_t eid_mask_length;
lisp_addr_t *eid_prefix;
uint16_t ms_udp_port;
uint16_t etr_udp_port;
lisp_addr_t *global_etr_rloc;
lisp_addr_t *ms_rloc;
lisp_addr_t *private_etr_rloc;
lisp_addr_list_t *rtr_rloc_list;

{
    uint32_t packet_len;

    lispd_pkt_info_nat_t *info_reply_pkt;





    if ((info_reply_pkt = build_info_reply_pkt(nonce,
                                               ttl,
                                               eid_mask_length,
                                               eid_prefix,
                                               ms_udp_port,
                                               etr_udp_port,
                                               global_etr_rloc,
                                               ms_rloc,
                                               private_etr_rloc,
                                               rtr_rloc_list,
                                               &packet_len)) == NULL) {
        syslog(LOG_DAEMON, "Couldn't build info reply packet");
        return (ERROR);
    }




    if (ERROR == complete_auth_fields(key_type,
                                      &(info_reply_pkt->key_id),
                                      key,
                                      info_reply_pkt,
                                      packet_len,
                                      info_reply_pkt->auth_data)) {
        free(info_reply_pkt);
        syslog(LOG_DAEMON, "HMAC failed for info-reply");
        return (ERROR);
    }

    //printf("Waiting...\n");

    //sleep(6);


    if (ERROR == send_packet(info_reply_pkt,
                             packet_len,
                             ms_rloc,
                             ms_udp_port, 
                             global_etr_rloc, 
                             etr_udp_port)) {
								 
        syslog_with_address_name(LOG_DAEMON,
                                 "Couldn't send info-reply for",
                                 eid_prefix);
        free(info_reply_pkt);
        return (ERROR);
    }

    free(info_reply_pkt);
    return (NO_ERROR);
}



int process_ecm_map_register_msg(uint8_t * packet, 
                                 int s,
                                 struct sockaddr *from,
                                 int afi)
{

    //void *cur_ptr;
    //lisp_encap_control_hdr_t *encap_control_hdr;

    struct ip *ip_hdr;
    lispd_pkt_map_register_t *map_reg_pkt;

    unsigned int map_reg_pkt_len;

    struct udphdr *udp_hdr;

    unsigned int from_port;
    unsigned int dest_port;

    lisp_addr_t from_addr;
    lisp_addr_t dest_addr;

	unsigned int ecm_from_port = 0;
    lisp_addr_t ecm_from_addr;
	
    printf("## Recieved ECM map register ##\n");


    //We get the global mn address from the outer header of ecm mrg msg
    if (get_source_address_and_port
        (from, &ecm_from_addr, (uint16_t *) &ecm_from_port) == ERROR) {
        syslog(LOG_DAEMON,
               "process_ecm_map_register. Error retrieving source address and port");
        return (ERROR);
    }
	
    ip_hdr = (struct ip *) CO((void *) packet, sizeof(lisp_encap_control_hdr_t));

    dest_addr.address.ip = ip_hdr->ip_dst;
    dest_addr.afi = AF_INET;


    //We get the local mn address from the inner header of ecm mrg msg
    local_mn_rloc.address.ip = ip_hdr->ip_src;
    local_mn_rloc.afi = AF_INET;


    //We have to change the source address for our own
    //Hardcoded code 
    from_addr = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);

    udp_hdr = (struct udphdr *) CO((void *) ip_hdr, sizeof(struct ip));

    from_port = ntohs(udp_hdr->source);
    dest_port = ntohs(udp_hdr->dest);

    map_reg_pkt_len = ntohs(udp_hdr->len) - sizeof(struct udphdr);

    map_reg_pkt = (lispd_pkt_map_register_t *) CO((void *) udp_hdr, sizeof(struct udphdr));

    

	/* To avoid residual ECM Map Requests*/
	if (map_reg_pkt->lisp_type != LISP_MAP_REGISTER){
		syslog(LOG_DAEMON,
               "process_ecm_map_register. No an ECM Map Register message");
		return(ERROR);
		
	}

	
	global_mn_rloc = ecm_from_addr;
	global_mn_port = ecm_from_port;


	printf("Global MN RLOC\n");
    print_address(&global_mn_rloc);
    printf("Local MN RLOC\n");
    print_address(&local_mn_rloc);

    printf("Global MN port: %d\n", global_mn_port);

	printf("Map Reg packet length: %d\n", map_reg_pkt_len);
	
    /*
       printf("From addr\n");
       print_address (&from_addr);
       printf("Dest addr\n");
       print_address (&dest_addr);

       printf("From port: %d\n",from_port);
       printf("Dest port: %d\n",dest_port);

       printf("Map Register type %d\n",map_reg_pkt->lisp_type);
     */


    send_packet((void *) map_reg_pkt,
                map_reg_pkt_len, 
                &from_addr,
                from_port, 
                &dest_addr, 
                dest_port);

    return (NO_ERROR);
}


int rtr_process_map_notify_msg(uint8_t *packet, 
                               int s,
                               struct sockaddr *from, 
                               int afi)
{


    lispd_pkt_map_notify_t *map_notify_pkt;

    unsigned int map_notify_pkt_len;

    lisp_addr_t ms_rloc;

    unsigned int ms_port;

    lisp_addr_t rtr_address;


    printf("## Recieved Map Notify ##\n");

    map_notify_pkt = (lispd_pkt_map_notify_t *) packet;

    //Turbo hardcoded. One EID, one RLOC. All IPv4.
    map_notify_pkt_len = 64;


    if (get_source_address_and_port(from, &ms_rloc, (uint16_t *) &ms_port) == ERROR) {
        syslog(LOG_DAEMON,"process_info_request. Error retrieving source address and port");
        return (ERROR);
    }


    rtr_address = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);


    build_and_send_data_map_notify(map_notify_pkt,
                                   map_notify_pkt_len,
                                   &ms_rloc,
                                   &local_mn_rloc,
                                   LISP_CONTROL_PORT,
                                   LISP_CONTROL_PORT,
                                   &rtr_address,
                                   &global_mn_rloc,
                                   LISP_CONTROL_PORT, 
                                   global_mn_port);

    return (NO_ERROR);

}

 
/*
 *  process Map_Register Message
 *  Receive a Map_register message and process based on control bits
 *  TODO Check authentication data
 */

int process_map_register_msg(uint8_t * packet, 
                             int s,
                             struct sockaddr *from, 
                             int afi)
{ 

    lispd_pkt_map_register_t *msg;

    lispd_pkt_mapping_record_locator_t *record_locator;

    lispd_pkt_mapping_record_t *mapping_record;

    void *cur_ptr;

    int i, j;

    uint8_t lisp_type;
    uint8_t proxy_reply;

    //uint8_t notify;

    uint8_t record_count;
    //uint64_t nonce;
    //uint16_t key_id;
    //uint16_t auth_data_len;
    //uint8_t auth_data[LISP_SHA1_AUTH_DATA_LEN];


    uint32_t ttl;
    uint8_t locator_count;
    //uint8_t eid_prefix_length;

    //uint8_t action;
    //uint8_t authoritative;

    //uint8_t version_hi;

    //uint8_t version_low;
    uint16_t eid_prefix_afi_inet;

    uint16_t locator_afi_inet;

    char *locator_char;

    //char eid_char[INET_ADDRSTRLEN];

    char *eid_name;

    //lisp_addr_t *eid_addr;

    printf("## PROCESING MAP REGISTER ##\n");
    syslog(LOG_DAEMON, "## PROCESING MAP REGISTER ##");

    msg = (lispd_pkt_map_register_t *) packet;


    lisp_type = msg->lisp_type;

    printf("lisp_type %d\n", lisp_type);

    proxy_reply = msg->proxy_reply;

    printf("proxy bit %d\n", proxy_reply);

    record_count = msg->record_count;

    printf("record count %d\n", record_count);

    /*
     * auth_data has (or will have) variable lentgh
     *
     * cur_ptr = CO(&(msg->auth_data), LISP_SHA1_AUTH_DATA_LEN*sizeof(uint8_t));
     */

    cur_ptr = CO((void *) msg, sizeof(lispd_pkt_map_register_t));



    for (i = 0; i < record_count; i++) {

        mapping_record = cur_ptr;

        ttl = ntohl(mapping_record->ttl);

        printf("ttl %d\n", ttl);

        locator_count = mapping_record->locator_count;

        printf("locator count %d\n", locator_count);

        eid_prefix_afi_inet = lisp2inetafi(ntohs(mapping_record->eid_prefix_afi));

        printf("edi_prefix_afi %d\n", eid_prefix_afi_inet);

        cur_ptr = CO(cur_ptr, sizeof(lispd_pkt_mapping_record_t));



        if ((eid_name = (char *) malloc(get_ntop_lisp_length(eid_prefix_afi_inet))) == NULL) {
            syslog(LOG_DAEMON, "malloc (eid_name): %s", strerror(errno));
            return (0);
        }

        eid_name = inet_ntop_char(cur_ptr, eid_name, eid_prefix_afi_inet);

        printf("eid name %s\n", eid_name);

        free(eid_name);




        cur_ptr = CO(cur_ptr, get_addr_len(eid_prefix_afi_inet));

        for (j = 0; j < locator_count; j++) {
            record_locator = cur_ptr;


            locator_afi_inet = lisp2inetafi(ntohs(record_locator->locator_afi));

            printf("locator afi %d\n", locator_afi_inet);

            printf("locator prior %d\n", record_locator->priority);

            printf("locator weigth %d\n", record_locator->weight);

            printf("locator mprior %d\n", record_locator->mpriority);

            printf("locator mweigth %d\n", record_locator->mweight);



            cur_ptr = CO(cur_ptr, sizeof(lispd_pkt_mapping_record_locator_t));

            if ((locator_char = (char *) malloc(get_ntop_lisp_length(locator_afi_inet))) == NULL) {
                syslog(LOG_DAEMON, "malloc (locator_char): %s", strerror(errno));
                return (0);
            }

            locator_char = inet_ntop_char(cur_ptr, locator_char, locator_afi_inet);

            printf("locator char %s\n", locator_char);

            free(locator_char);



            cur_ptr = CO(cur_ptr, get_addr_len(locator_afi_inet));

        }

    }

    return (1);
}


/**************************************************************/
/**************************************************************/
/************** NO LONGER IN USE FUNCTIONS. *******************/
/**************************************************************/
/**************************************************************/



/*

int add_basic_cache_entry(lisp_addr_t * eid, lisp_addr_t * rloc,
                          int length)
{
    lisp_eid_map_msg_t *map_msg;
    int map_msg_len;

    int ret;



    map_msg_len = sizeof(lisp_eid_map_msg_t) + sizeof(lisp_eid_map_msg_loc_t);  // * loc_count;
    if ((map_msg = malloc(map_msg_len)) == NULL) {
        syslog(LOG_DAEMON,
               "add_basic_cache_entry(), malloc (map-cache entry): %s",
               strerror(errno));
        return (ERROR);
    }

    memset(map_msg, 0, sizeof(lisp_eid_map_msg_t));



    memcpy(&(map_msg->eid_prefix), eid, sizeof(lisp_addr_t));
    map_msg->eid_prefix.afi = eid->afi;
    map_msg->eid_prefix_length = length;
    map_msg->count = 1;
    map_msg->actions = 0;
    map_msg->how_learned = STATIC_MAP_CACHE_ENTRY;      // Is this correct?     
    map_msg->ttl = 60;          // XXX TODO How much time to put here?
    map_msg->sampling_interval = RLOC_PROBING_INTERVAL; // How much time to put here?




    map_msg->sampling_interval = 0;
    // Fill in locator data 
    memcpy(&(map_msg->locators[0].locator.address), &(rloc->address),
           sizeof(lisp_addr_t));
    map_msg->locators[0].locator.afi = rloc->afi;
    map_msg->locators[0].priority = 1;
    map_msg->locators[0].weight = 100;
    map_msg->locators[0].mpriority = 255;
    map_msg->locators[0].mweight = 100;

    ret = send_eid_map_msg(map_msg, map_msg_len);
#ifdef     DEBUG
    syslog(LOG_DAEMON, "Installed map cache entry");
#endif
    if (ret < 0) {
        syslog(LOG_DAEMON, "Installing map cache entry failed; ret=%d",
               ret);
        free(map_msg);
        map_msg = NULL;
        return (ERROR);
    }

    free(map_msg);
    map_msg = NULL;
    return (NO_ERROR);


}

*/



/*
 Old version to support IP options 
 */

/*

struct udphdr *build_ip_header_with_extra_len(cur_ptr, my_addr, eid_prefix,
                                              iph_extra_len, ip_len)
void *cur_ptr;
lisp_addr_t *my_addr;
lisp_addr_t *eid_prefix;
unsigned int iph_extra_len;
unsigned int ip_len;
{
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;

    switch (my_addr->afi) {
    case AF_INET:
        iph = (struct ip *) cur_ptr;
        iph->ip_hl = 5 + (iph_extra_len / 4);   // Number of bytes / 4 = number of 32 bits rows 
        iph->ip_v = IPVERSION;
        iph->ip_tos = 0;
        iph->ip_len = htons(ip_len);
        iph->ip_id = htons(54321);
        iph->ip_off = 0;
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_sum = 0;
        iph->ip_src.s_addr = my_addr->address.ip.s_addr;
        iph->ip_dst.s_addr = eid_prefix->address.ip.s_addr;
        udph = (struct udphdr *) CO(iph, sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc = (IP6VERSION << 4);
        ip6h->ip6_nxt = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len);
        memcpy(ip6h->ip6_src.s6_addr,
               my_addr->address.ipv6.s6_addr, sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,
               eid_prefix->address.ipv6.s6_addr, sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h, sizeof(struct ip6_hdr));
        break;
    default:
        return (0);
    }
    return (udph);
}

*/

/* 
  Old version with IP options 
 */

/*
uint8_t *build_data_encap_pkt_with_ip_options(uint8_t * orig_pkt,
                                              unsigned int orig_pkt_len,
                                              lisp_addr_t * addr_from,
                                              lisp_addr_t * addr_dest,
                                              unsigned int port_from,
                                              unsigned int port_dest,
                                              int ip_opt,
                                              unsigned int *encap_pkt_len)
{
    uint8_t *cur_ptr;
    void *pkt_ptr;

    void *iph_ptr;
    struct udphdr *udph_ptr;



    unsigned int epkt_len;
    unsigned int ip_hdr_len;
    unsigned int udp_hdr_len;
    unsigned int ip_opt_len;
    unsigned int lisp_hdr_len;

    unsigned int ip_payload_len;
    unsigned int udp_payload_len;

    uint16_t udpsum = 0;


    if (addr_from->afi != addr_dest->afi) {
        syslog(LOG_DAEMON, "data_encap_pkt: Different AFI addresses");
        return (NULL);
    }

    // IP options length 

    switch (addr_from->afi) {
    case AF_INET:

        switch (ip_opt) {
        case NO_IP_OPTION:
            ip_opt_len = 0;
            break;
        case ROUTE_ALERT:
            ip_opt_len = 4;     // 4 bytes 
            break;
        default:
            syslog(LOG_DAEMON, "data_encap_pkt: Unsupported IP option %d",
                   ip_opt);
            return (NULL);
        }

        break;
    case AF_INET6:
        ip_opt_len = 0;
        break;

    default:
        syslog(LOG_DAEMON, "data_encap_pkt: Unknown AFI %d",
               addr_from->afi);
        return (NULL);


    }

    // Headers lengths 

    lisp_hdr_len = 8;           // 8 bytes 

    ip_hdr_len = get_ip_header_len(addr_from->afi);

    udp_hdr_len = sizeof(struct udphdr);



    epkt_len = lisp_hdr_len +
        ip_hdr_len + ip_opt_len + udp_hdr_len + orig_pkt_len;

    if ((pkt_ptr = (void *) malloc(epkt_len)) == NULL) {
        syslog(LOG_DAEMON, "malloc(packet_len): %s", strerror(errno));
        return (NULL);
    }

    memset(pkt_ptr, 0, epkt_len);


    // LISP header 
    // All the lisp header fields left with 0 value 

    cur_ptr = (void *) CO(pkt_ptr, lisp_hdr_len);

    iph_ptr = cur_ptr;

    // IP header 

    ip_payload_len = ip_hdr_len + ip_opt_len + udp_hdr_len + orig_pkt_len;

    cur_ptr = (void *) build_ip_header_with_extra_len(iph_ptr,
                                                      addr_from,
                                                      addr_dest,
                                                      ip_opt_len,
                                                      ip_payload_len);

    // Support just Route Alert option by the moment. 
    // Ignore other options. 

    if (ip_opt == ROUTE_ALERT) {

        // Putting by hand the IP Option Route Alert Values
        //
        // Route Alert
        // +--------+--------+--------+--------+
        // |10010100|00000100|00000000 00000000|
        // +--------+--------+--------+--------+

        


        cur_ptr[0] = 148;       // 10010100 
        cur_ptr[1] = 4;         // 00000100
        cur_ptr[2] = 0;         // 00000000 
        cur_ptr[3] = 0;         // 00000000
    }


    // UDP header 

    udph_ptr = (void *) CO(cur_ptr, ip_opt_len);

    udp_payload_len = udp_hdr_len + orig_pkt_len;

#ifdef BSD
    udph_ptr->uh_sport = htons(port_from);
    udph_ptr->uh_dport = htons(port_dest);
    udph_ptr->uh_ulen = htons(udp_payload_len);
    udph_ptr->uh_sum = 0;
#else
    udph_ptr->source = htons(port_from);
    udph_ptr->dest = htons(port_dest);
    udph_ptr->len = htons(udp_payload_len);
    udph_ptr->check = 0;
#endif

    // Copy original packet after the data packet headers 

    cur_ptr = (void *) CO(udph_ptr, udp_hdr_len);

    memcpy(cur_ptr, orig_pkt, orig_pkt_len);


    
     // Now compute the headers checksums
     


    ((struct ip *) iph_ptr)->ip_sum =
        ip_checksum(iph_ptr, ip_hdr_len + ip_opt_len);

    if ((udpsum =
         udp_checksum(udph_ptr, udp_payload_len, iph_ptr,
                      addr_from->afi)) == -1) {
        return (ERROR);
    }
    udpsum(udph_ptr) = udpsum;


    // Return the encapsulated packet and its length 

    *encap_pkt_len = epkt_len;

    return (pkt_ptr);

}

*/
