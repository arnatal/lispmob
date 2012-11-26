#include "lispd_output.h"




void add_ipv4_header ( char *position,
                 char *original_packet_position,
                 lisp_addr_t *src_addr,
                 lisp_addr_t *dst_addr) {


    struct iphdr *iph;
    struct iphdr *inner_iph;


    /*
     * Construct and add the outer ip header
     */

    iph = ( struct iphdr * ) position;
    inner_iph = ( struct iphdr * ) original_packet_position;


    //arnatal TODO: check inner ip header version to proper copy tos and ttl fields

    iph->version  = 4;
    iph->ihl      = sizeof ( struct iphdr ) >>2;
    iph->frag_off = 0;   // XXX recompute above, use method in 5.4.1 of draft
    iph->protocol = IPPROTO_UDP;

    iph->tos      = inner_iph->tos;

    iph->daddr    = dst_addr->address.ip.s_addr;
    iph->saddr    = src_addr->address.ip.s_addr;

    iph->ttl      = inner_iph->ttl;


    //arnatal XXX: Checksum?

    //iph->check = ip_checksum((uint16_t*) iph, sizeof(struct iphdr));

    //if ((udpsum = udp_checksum(udh, pckt_length - iph_len, packet_buf, AF_INET)) == -1) {
    //    return (0);
    //}
    //udh->check = udpsum;

}

void add_udp_header(char *position,
              int length,
              int src_port,
              int dst_port){

    struct udphdr *udh;


    /*
     * Construct and add the udp header
     */
    udh = ( struct udphdr * ) position;

    /*
     * Hash of inner header source/dest addr. This needs thought.
     */
    udh->source = htons ( src_port ); //arnatal TODO: Selec source port based on tuple?
    udh->dest =  htons ( dst_port );
    udh->len = htons ( sizeof ( struct udphdr ) + length );
    //udh->len = htons(sizeof(struct udphdr)); /* Wireshark detects this as error*/
    udh->check = 0; // SHOULD be 0 as in LISP ID


}

void add_lisp_header(char *position,
                     int iid){

    struct lisphdr *lisphdr;

    lisphdr = (struct lisphdr *) position;

    lisphdr->instance_id = iid;

    /* arnatal TODO: support for the rest of values*/
    lisphdr->echo_nonce = 0;
    lisphdr->lsb = 0;
    lisphdr->lsb_bits = 0;
    lisphdr->map_version = 0;
    lisphdr->nonce[0] = 0;
    lisphdr->nonce[1] = 0;
    lisphdr->nonce[2] = 0;
    lisphdr->nonce_present = 0;
    lisphdr->rflags = 0;

}

int encapsulate_packet(char *original_packet,
                    int original_packet_length,
                    int encap_afi,
                    lisp_addr_t *src_addr,
                    lisp_addr_t *dst_addr,
                    int src_port,
                    int dst_port,
                    int iid,
                    char **encap_packet,
                    int  *encap_packet_size){


    int extra_headers_size;
    char *new_packet;

    int iphdr_len;
    int udphdr_len;
    int lisphdr_len;

    switch (encap_afi){
        case AF_INET:
            iphdr_len = sizeof(struct iphdr);
            break;
        case AF_INET6:
            //arnatal TODO: write IPv6 support
            break;
    }
    
    
    udphdr_len = sizeof(struct udphdr);
    lisphdr_len = sizeof(struct lisphdr);

    extra_headers_size = iphdr_len + udphdr_len + lisphdr_len;

    new_packet = (char *) malloc (original_packet_length + extra_headers_size);

    if (new_packet == NULL){
        syslog(LOG_ERR, "Can not IPv4 encap packet ");
        return BAD;
    }

    memset(new_packet,0,original_packet_length+extra_headers_size);

    memcpy (new_packet + extra_headers_size, original_packet, original_packet_length);



    add_lisp_header((char *)(new_packet + iphdr_len + udphdr_len), iid);

    add_udp_header((char *)(new_packet + iphdr_len),original_packet_length+lisphdr_len,src_port,dst_port);

    
    switch (encap_afi){
        case AF_INET:
            add_ipv4_header((char *)(new_packet),original_packet,src_addr,dst_addr);
            break;
        case AF_INET6:
            //arnatal TODO: write IPv6 support
            break;
    }

    *encap_packet = new_packet;
    *encap_packet_size = extra_headers_size + original_packet_length;

    return GOOD;
}



int send_by_raw_socket ( lispd_iface_elt *iface, char *packet_buf, int pckt_length ) {

    int socket;

    struct sockaddr *dst_addr;
    int dst_addr_len;
    struct sockaddr_in dst_addr4;
    //struct sockaddr_in6 dst_addr6;
    struct iphdr *iph;
    int nbytes;


    memset ( ( char * ) &dst_addr, 0, sizeof ( dst_addr ) );


    iph = ( struct iphdr * ) packet_buf;

    if ( iph->version == 4 ) {
        memset ( ( char * ) &dst_addr4, 0, sizeof ( dst_addr4 ) );
        dst_addr4.sin_family = AF_INET;
        dst_addr4.sin_port = htons ( LISP_DATA_PORT );
        dst_addr4.sin_addr.s_addr = iph->daddr;

        dst_addr = ( struct sockaddr * ) &dst_addr4;
        dst_addr_len = sizeof ( struct sockaddr_in );
        socket = iface->out_socket_v4;
    } else {
        //arnatal TODO: write IPv6 support
    }

    printf ( "Trying to send in Socket %d\n",iface->out_socket_v4 );


    nbytes = sendto ( socket,
                      ( const void * ) packet_buf,
                      pckt_length,
                      0,
                      dst_addr,
                      dst_addr_len );

    if ( nbytes != pckt_length ) {
        syslog ( LOG_DAEMON, "send_by_raw_socket: send failed %s", strerror ( errno ) );
        return ( BAD );
    }

    printf ( "packet sent\n" );

    return GOOD;

}

int fordward_native( lispd_iface_elt *iface, char *packet_buf, int pckt_length ){

    int ret;
    
    syslog(LOG_INFO, "Fordwarding native for destination %s",
                        get_char_from_lisp_addr_t(extract_dst_addr_from_packet(packet_buf)));

    if(send_by_raw_socket(iface,packet_buf,pckt_length) != GOOD){
        ret = BAD;
    }else{
        ret = GOOD;
    }

    free(packet_buf);
    
    return ret;
    
}


int fordward_to_petr(lispd_iface_elt *iface, char *original_packet, int original_packet_length, int afi){

    lisp_addr_t *petr;
    lisp_addr_t *outer_src_addr;
    char *encap_packet;
    int  encap_packet_size;
    
    petr = get_proxy_etr(afi); 
    
    if (petr == NULL){
        syslog(LOG_ERR, "Proxy-etr not found");
        return BAD;
    }

    syslog(LOG_DEBUG, "Proxy-etr found: %s",get_char_from_lisp_addr_t(*petr));
    
    switch (afi){
        case AF_INET:
            outer_src_addr = iface->ipv4_address;
            break;
        case AF_INET6:
            //arnatal TODO: write IPv6 support
            break;
    }

    if (encapsulate_packet(original_packet,
                            original_packet_length,
                            afi,
                            outer_src_addr,
                            petr,
                            LISP_DATA_PORT,
                            LISP_DATA_PORT,
                            0,
                            &encap_packet,
                            &encap_packet_size) != GOOD){
        free(original_packet);
        return BAD;
    }
    free(original_packet);
    
    if (send_by_raw_socket (iface,encap_packet,encap_packet_size ) != GOOD){
        free (encap_packet );
        return BAD;
    }

    syslog(LOG_INFO, "Fordwarded eid %s to petr",get_char_from_lisp_addr_t(extract_dst_addr_from_packet(original_packet)));
    free (encap_packet );
    
    return GOOD;
}

lisp_addr_t extract_dst_addr_from_packet ( char *packet ) {
    lisp_addr_t addr;
    struct iphdr *iph;
    struct ip6_hdr *ip6h;

    iph = (struct iphdr *) packet;

    if ( iph->version == 4 ) {
        addr.afi = AF_INET;
        addr.address.ip.s_addr = iph->daddr;


    } else {
        ip6h = (struct ip6_hdr *) packet;
        addr.afi = AF_INET6;
        addr.address.ipv6 = ip6h->ip6_dst;
    }

    //arnatal TODO: check errors (afi unsupported)

    return addr;
}


int handle_map_cache_miss(lisp_addr_t *eid){

    lispd_map_cache_entry *entry;


    //arnatal TODO: check if this works
    entry = new_map_cache_entry(*eid,get_prefix_len(eid->afi),DYNAMIC_MAP_CACHE_ENTRY,DEFAULT_DATA_CACHE_TTL);

    //arnatal TODO: check errors

    
    return GOOD;
}

lisp_addr_t *get_proxy_etr(int afi){

    lisp_addr_t * petr;
    
    if(proxy_etrs!=NULL){
        petr = proxy_etrs->address;
    }else{
        petr = NULL;
    }

    return petr;
}


void process_output_packet ( int fd, char *tun_receive_buf, unsigned int tun_receive_size ) {
    int nread;
    struct iphdr *iph;
    
    nread = read ( fd, tun_receive_buf, tun_receive_size );
    
    printf ( "In tuntap_process_output_packet\n" );
    
        
    lisp_output ( tun_receive_buf, nread );
}


int lisp_output ( char *original_packet, int original_packet_length ) {
    lispd_iface_elt *iface;
    
    char *encap_packet;
    int  encap_packet_size;
    lisp_addr_t *outer_dst_addr;
    int map_cache_query_result;
    lisp_addr_t *outer_src_addr;
    lisp_addr_t original_dst_addr;
    lispd_map_cache_entry *entry;
    
    int encap_afi;
    
    
    //arnatal: TODO: Check if local -> Do not encapsulate
    //arnatal: TODO: Check if lisp packet (control or already encapsulated)
    
    original_dst_addr = extract_dst_addr_from_packet(original_packet);
    syslog(LOG_DEBUG,"Packet received dst. to: %s\n",get_char_from_lisp_addr_t(original_dst_addr));
    
    encap_afi = original_dst_addr.afi; //arnatal TODO: how tho choose encapsulation api?
    
    //arnatal XXX TODO check if this works
    map_cache_query_result = lookup_eid_cache(original_dst_addr,&entry);
    
    //arnatal TODO: check if this is the correct error type
    if (map_cache_query_result == ERR_DB){ /* There is no entry in the map cache */
        syslog(LOG_INFO, "No map cache retrieved for eid %s",get_char_from_lisp_addr_t(original_dst_addr));
        
        handle_map_cache_miss(&original_dst_addr);
    }
    
    if ((map_cache_query_result != GOOD) || (entry->active == NO_ACTIVE)){ /* There is no entry or is not active*/
        
        /* Try to fordward to petr*/
        if (fordward_to_petr(get_default_output_iface(encap_afi), /* Use afi of original dst for encapsulation */
            original_packet,
            original_packet_length,
            encap_afi) != GOOD){
            /* If error, fordward native*/
            fordward_native(get_default_output_iface(encap_afi),
                original_packet,
                original_packet_length);
            }
            return GOOD;
    }
    
    /* There is an entry in the map cache */
    
    iface = get_default_output_iface(encap_afi);
    
    
    switch(encap_afi){ //arnatal XXX: is this necessary? Maybe changing the names of head_vX_locator_list, etc...
        case AF_INET:
            outer_dst_addr = entry->identifier->head_v4_locators_list->locator->locator_addr;
            outer_src_addr = iface->ipv4_address;
            break;
        case AF_INET6:
            outer_dst_addr = entry->identifier->head_v6_locators_list->locator->locator_addr;
            outer_src_addr = iface->ipv6_address;
            break;
    }
    
    
    encapsulate_packet(original_packet,
                       original_packet_length,
                       encap_afi,
                       outer_src_addr,
                       outer_dst_addr,
                       LISP_DATA_PORT,
                       LISP_DATA_PORT,
                       entry->identifier->iid,
                       &encap_packet,
                       &encap_packet_size);
    
    send_by_raw_socket (iface,encap_packet,encap_packet_size);
    
    free (encap_packet);
    free (original_packet);
    
    return GOOD;
}