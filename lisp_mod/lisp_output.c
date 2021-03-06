/*
 * lisp_output.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implements handler routines for locally sourced packets destined
 * for LISP encapsulation.
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
 *    Chris White       <chris@logicalelegance.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include "linux/version.h"
#include "linux/ip.h"
#include "linux/udp.h"
#include "linux/in_route.h"
#include "net/route.h"
#include "net/ip.h"
#include "net/ipv6.h"
#include "net/ip6_route.h"
#include "net/inet_ecn.h"
#include "net/dst.h"
#include "net/tcp.h"
#include "net/ip6_checksum.h"
#include "lisp_mod.h"
#include "lisp_output.h"
#include "packettypes.h"

#define DEBUG 
//#define DEBUG_PACKETS

/* PN 
 * define NEW_KERNEL to handle differences in struct sk_buff
 * between android and newer kernels
 */
#define NEW_KERNEL

#define LISP_EID_INTERFACE    "lmn0"

extern lisp_globals globals;

static inline uint16_t src_port_hash(struct iphdr *iph)
{
  uint16_t result = 0;

  // Simple rotated XOR hash of src and dst
  result = (iph->saddr << 4) ^ (iph->saddr >> 28) ^ iph->saddr ^ iph->daddr;
  return result;
}

static inline unsigned char output_hash_v4(unsigned int src_eid, unsigned int dst_eid)
{
	uint32_t hash, aux_addr, i;
	uint8_t byte;

	aux_addr = src_eid ^ dst_eid;
	for(hash = i = 0; i < 4; ++i)
	{
		byte = aux_addr & 0xFF;
		aux_addr = aux_addr >> 8;
		hash += byte;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return ( hash % LOC_HASH_SIZE);
}

static inline unsigned char output_hash_v6(struct in6_addr src_eid, struct in6_addr dst_eid)
{
	uint32_t hash, i;

	for(hash = i = 0; i < 4; ++i)
	{
		hash += src_eid.in6_u.u6_addr8[i] ^ dst_eid.in6_u.u6_addr8[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return ( hash % LOC_HASH_SIZE);
}

/*
 * is_addrv4_local_eid
 *
 * Checks whether the source address in ip header corresponds to an EID assigned to
 * the host.
 */

bool is_addrv4_local_eid(struct iphdr *iph){
	int i;
	for(i=0;i<globals.num_local_eid;i++){
		if(iph->saddr==globals.local_eid_list[i].address.ip.s_addr){
			return 1;
		}
	}
	return 0;
}

/*
 * is_addrv6_local_eid
 *
 * Checks whether the source address in ip header corresponds to an EID assigned to
 * the host.
 */

bool is_addrv6_local_eid(struct ipv6hdr *iph){
	int i;
	for(i=0;i<globals.num_local_eid;i++){
		if(ipv6_addr_equal(&iph->saddr,&globals.local_eid_list[i].address.ipv6)){
			return 1;
		}
	}
	return 0;
}

uint32_t get_rloc_address_from_skb(struct sk_buff *skb)
{
    rloc_map_entry_t *entry;

    entry = globals.if_to_rloc_hash_table[skb->mark & ((1<< IFINDEX_HASH_BITS) - 1)];

    while (entry) {
        if (entry->ifindex == skb->mark) {
            break;
        }
        entry = entry->next;
    }
    if (!entry) {
        return 0;
    }

    printk(KERN_INFO "  Using source RLOC %pi4 from ifindex: %d", &entry->addr.address.ip.s_addr, entry->ifindex);
    return entry->addr.address.ip.s_addr;
}

void lisp_encap4(struct sk_buff *skb, int locator_addr,
		 ushort inner_afi)
{
  struct udphdr *udh;
  struct iphdr *iph;
  struct iphdr *old_iph = ip_hdr(skb);
  struct lisphdr *lisph;
  struct sk_buff *new_skb = NULL;
  uint32_t orig_length = skb->len;
  uint32_t pkt_len, err;
  uint32_t max_headroom;
  struct net_device *tdev; // Output device
  struct rtable *rt; // route to RLOC
  uint32_t rloc = 0;

  if (globals.multiple_rlocs) {
      rloc = get_rloc_address_from_skb(skb);
  } else {
      if (globals.if_to_rloc_hash_table[0]) {
          rloc = globals.if_to_rloc_hash_table[0]->addr.address.ip.s_addr;
      }
  }

  if (!rloc) {
      printk(KERN_INFO "Unable to determine source rloc for ifindex: %d", skb->mark);
      return;
  }

  /*
   * Painful: we have to do a routing check on our
   * proposed RLOC dstadr to determine the output
   * device. This is so that we can be assured
   * of having the proper space available in the 
   * skb to add our headers. This is modelled after
   * the ipip.c code.
   */
   /*
    * PN: Set correct saddr for route lookup
    */
    printk(KERN_INFO "lisp_encap4: saddr for route lookup: %pI4\n",
                      &rloc);
  {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
    struct flowi fl;
    fl.flowi_oif   = 0;
    fl.flowi_tos   = RT_TOS(old_iph->tos);
    fl.flowi_proto = IPPROTO_UDP;
    fl.u.ip4.daddr = locator_addr;
    fl.u.ip4.saddr = rloc;
    rt = ip_route_output_key(&init_net, &fl.u.ip4);
    if (IS_ERR(rt)) {
#else
    struct flowi fl = { .oif = 0,
			.nl_u = { .ip4_u = 
				  { .daddr = locator_addr,
                                    .saddr = rloc,
				    .tos = RT_TOS(old_iph->tos) } },
			.proto = IPPROTO_UDP };
    if (ip_route_output_key(&init_net, &rt, &fl)) {
#endif
      printk(KERN_INFO "Route lookup for locator %pI4 failed\n", &locator_addr);
      /*
       * PN: Fix skb memory leaks
       */
      dev_kfree_skb(skb);
      return;
    }
  }
  
  /*
   * Get the output device 
   */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  tdev = rt->dst.dev;
#else
  tdev = rt->u.dst.dev;
#endif
  
  /*
   * PN: What did route lookup return?
   */
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "   Got route for RLOC; tdev: %s\n", tdev->name);
#endif

  /*
   * Handle fragmentation XXX 
   */
  
  /* 
   * Determine if we have enough space.
   */
  max_headroom = (LL_RESERVED_SPACE(tdev) + sizeof(struct iphdr) +
		  sizeof(struct udphdr) + sizeof(struct lisphdr));
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "    Max headroom is %d\n", max_headroom);
#endif

  /*
   * If not, gotta make some more.
   */
  if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
      (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
#ifdef DEBUG_PACKETS
    printk(KERN_INFO "    Forced to allocate new sk_buff\n");
#endif
    new_skb = skb_realloc_headroom(skb, max_headroom);
    if (!new_skb) {
      ip_rt_put(rt);
      printk(KERN_INFO "Failed to allocate new skb for packet encap\n");
      /*
       * PN: Fix skb memory leaks
       */
      dev_kfree_skb(skb);
      return;
    }

    /*
     * Repoint socket if necessary
     */
    if (skb->sk) 
      skb_set_owner_w(new_skb, skb->sk);

    dev_kfree_skb(skb);
    skb = new_skb;
    old_iph = ip_hdr(skb);
  }

  /* 
   * Construct and add the LISP header
   */
  lisph = (struct lisphdr *)(skb_push(skb, sizeof(struct lisphdr)));
  skb_reset_transport_header(skb);

  memset((char *)lisph, 0, sizeof(struct lisphdr));

  // Single LSB for now, and set it to ON
  lisph->lsb = 1;
  lisph->lsb_bits = htonl(0x1);

  /*
   * Using instance ID? Or it in.
   */
  if (globals.use_instance_id) {
      lisph->instance_id = 1;
      lisph->lsb_bits |= htonl(globals.instance_id << 8);
  }

  lisph->nonce_present = 1;
  lisph->nonce[0] = net_random() & 0xFF;
  lisph->nonce[1] = net_random() & 0xFF;
  lisph->nonce[2] = net_random() & 0xFF;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "          rflags: %d, e: %d, l: %d, n: %d, i: %d, id/lsb: 0x%x",
             lisph->rflags, lisph->echo_nonce, lisph->lsb,
             lisph->nonce_present, lisph->instance_id, ntohl(lisph->lsb_bits));
#endif

  /* 
   * Construct and add the udp header
   */ 
  udh = (struct udphdr *)(skb_push(skb, sizeof(struct udphdr)));
  skb_reset_transport_header(skb);

  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(globals.udp_encap_port);
  udh->dest =  htons(LISP_ENCAP_PORT);
  udh->len = htons(sizeof(struct udphdr) + orig_length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ip header
   */
  skb->transport_header = skb->network_header;
  iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
  skb_reset_network_header(skb);
  memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
  IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
                                IPSKB_REROUTED);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  skb_dst_drop(skb);
  skb_dst_set(skb, &rt->dst);
#elif defined NEW_KERNEL
  skb_dst_drop(skb);
  skb_dst_set(skb, &rt->u.dst);
#else
  dst_release(skb->dst);
  skb->dst = &rt->u.dst;
#endif
  iph           = ip_hdr(skb);
  iph->version  =    4;
  iph->ihl      =     sizeof(struct iphdr)>>2;
  iph->frag_off = 0;   // XXX recompute above, use method in 5.4.1 of draft
  iph->protocol = IPPROTO_UDP;
  iph->tos      = old_iph->tos; // Need something else too? XXX
  iph->daddr    = rt->rt_dst;
  iph->saddr    = rloc;
  iph->ttl      = old_iph->ttl;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "     Packet encapsulated to %pI4 from %pI4\n",
	 &(iph->daddr), &(iph->saddr));
#endif
  nf_reset(skb);
  
  /* 
   * We must transmit the packet ourselves:
   * the skb has probably changed out from under
   * the upper layers that have a reference to it.
   * 
   * This is the same work that the tunnel code does
   */
  pkt_len = skb->len - skb_transport_offset(skb);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
  ip_select_ident(iph, &rt->dst, NULL);
#else
  ip_select_ident(iph, &rt->u.dst, NULL);
#endif

  /*
   * We want the equivalent of ip_local_output, but
   * without taking a pass through the NF_HOOK again.
   * We'd just come right back here. May be wary of
   * all this does too: fragmentation, etc.... XXX
   */
  iph->tot_len = htons(skb->len);
  ip_send_check(iph);

  err = dst_output(skb);
  if (net_xmit_eval(err) != 0) {
    printk(KERN_INFO "     ip_local_out() reported an error: %d\n", err);
    /*
     * PN: Fix skb memory leaks
     */
    dev_kfree_skb(skb);
  }

  return;
}

void lisp_encap6(struct sk_buff *skb, lisp_addr_t locator_addr,
		 ushort inner_afi)
{
  struct udphdr *udh;
  struct ipv6hdr *iph;
  struct ipv6hdr *old_iph = ipv6_hdr(skb);
  struct lisphdr *lisph;
  struct sk_buff *new_skb = NULL;
  uint32_t orig_length = skb->len;
  uint32_t pkt_len, err;
  uint32_t max_headroom;
  struct net_device *tdev; // Output device
  struct dst_entry *dst;
  int    mtu;
  uint8_t dsfield;
  struct flowi fl;
  lisp_addr_t *rloc = NULL;
  
  if (globals.multiple_rlocs) {
      //get_rloc_for_skb(rloc);
  } else {
      rloc = &globals.if_to_rloc_hash_table[0]->addr; // XXX should lock?
  }

  /*
   * We have to do a routing check on our
   * proposed RLOC dstadr to determine the output
   * device. This is so that we can be assured
   * of having the proper space available in the 
   * skb to add our headers. This is modelled after
   * the iptunnel6.c code.
   */
  {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
    memcpy(&fl.u.ip6.daddr, &locator_addr.address.ipv6, sizeof(struct in6_addr));
#else
    memcpy(&fl.fl6_dst, &locator_addr.address.ipv6, sizeof(struct in6_addr));
#endif
    if (rloc->afi != AF_INET6) {
      printk(KERN_INFO "No AF_INET6 source rloc available\n");
      return;
    }
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
    memcpy(&fl.u.ip6.saddr, &rloc->address.ipv6, sizeof(struct in6_addr));
    fl.flowi_oif = 0;

    fl.u.ip6.flowlabel = 0;
    fl.flowi_proto = IPPROTO_UDP;
  }

  dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);
#else
    memcpy(&fl.fl6_src, &rloc->address.ipv6, sizeof(struct in6_addr));
    fl.oif = 0;

    fl.fl6_flowlabel = 0;
    fl.proto = IPPROTO_UDP;
  }

  dst = ip6_route_output(&init_net, NULL, &fl);
#endif

  if (dst->error) {
    printk(KERN_INFO "  Failed v6 route lookup for RLOC\n");
    
    // Error fail cleanup XXX
    return;
  }
     
  /*
   * Get the output device 
   */
  tdev = dst->dev;
  
  printk(KERN_INFO "   Got route for RLOC\n");

  /*
   * Handle fragmentation XXX 
   */
  mtu = dst_mtu(dst) - (sizeof(*iph) + sizeof(*lisph));
  if (mtu < IPV6_MIN_MTU) {
    mtu = IPV6_MIN_MTU;
  };

#ifdef NEW_KERNEL
  /*
   * Do we really want to do this? XXX
   */
  if (skb_dst(skb))
    skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
  if (skb->len > mtu) {
    printk(KERN_INFO "   skb does not fit in MTU");
    return; // Cleanup XXX
  }
#else
  if (skb->dst)
      skb->dst->ops->update_pmtu(skb->dst, mtu);
  if (skb->len > mtu) {
      printk(KERN_INFO "   skb does not fit in MTU\n");
      return; // Cleanup XXX
  }
#endif
  
  /* 
   * Determine if we have enough space.
   */
  max_headroom = (LL_RESERVED_SPACE(tdev) + sizeof(struct ipv6hdr) +
		  sizeof(struct udphdr) + sizeof(struct lisphdr));
  printk(KERN_INFO "  Max headroom is %d\n", max_headroom);

  /*
   * If not, gotta make some more.
   */
  if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
      (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
      printk(KERN_INFO "  Forced to allocate new sk_buff\n");
      new_skb = skb_realloc_headroom(skb, max_headroom);
      if (!new_skb) {
          printk(KERN_INFO "Failed to allocate new skb for packet encap\n");
          return;
      }

      /*
     * Repoint socket if necessary
     */
      if (skb->sk)
          skb_set_owner_w(new_skb, skb->sk);

      dev_kfree_skb(skb);
      skb = new_skb;
      old_iph = ipv6_hdr(skb); // Err.. what if its v6 encaped v4? XXX
  }

#ifdef NEW_KERNEL
  skb_dst_drop(skb);
  skb_dst_set(skb, dst);
#else
  dst_release(skb->dst);
  skb->dst = dst_clone(dst);
#endif

  /* 
   * Construct and add the LISP header
   */
  skb->transport_header = skb->network_header;
  lisph = (struct lisphdr *)(skb_push(skb, sizeof(struct lisphdr)));
  skb_reset_transport_header(skb);

  // no flags XXX
  memset((char *)lisph, 0, sizeof(struct lisphdr));

   /* 
   * Construct and add the udp header
   */ 
  skb->transport_header = skb->network_header;
  udh = (struct udphdr *)(skb_push(skb, sizeof(struct udphdr)));
  skb_reset_transport_header(skb);
  
  /*
   * Hash of inner header source/dest addr. This needs thought.
   */
  udh->source = htons(globals.udp_encap_port);
  udh->dest =  LISP_ENCAP_PORT;
  udh->len = htons(sizeof(struct udphdr) + orig_length +
		   sizeof(struct lisphdr));
  udh->check = 0; // SHOULD be 0 as in LISP ID

  /*
   * Construct and add the outer ipv6 header
   */
  skb_push(skb, sizeof(struct ipv6hdr));
  skb_reset_network_header(skb);
  iph = ipv6_hdr(skb);
  *(__be32*)iph = htonl(0x60000000); // Flowlabel? XXX
  dsfield = INET_ECN_encapsulate(0, dsfield);
  ipv6_change_dsfield(iph, ~INET_ECN_MASK, dsfield);
  iph->hop_limit = 10; // XXX grab from inner header.
  iph->nexthdr = IPPROTO_UDP;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
  memcpy(&iph->saddr, &fl.u.ip6.saddr, sizeof(struct in6_addr));
  memcpy(&iph->daddr, &fl.u.ip6.daddr, sizeof(struct in6_addr));
#else
  memcpy(&iph->saddr, &fl.fl6_src, sizeof(struct in6_addr));
  memcpy(&iph->daddr, &fl.fl6_dst, sizeof(struct in6_addr));
#endif
  nf_reset(skb);

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "  Packet encapsulated to %pI6\n", iph->daddr.s6_addr);
#endif

  /* 
   * We must transmit the packet ourselves:
   * the skb has probably changed out from under
   * the upper layers that have a reference to it.
   * 
   * This is the same work that the tunnel code does
   */
  pkt_len = skb->len;
  err = ip6_local_out(skb);
  if (net_xmit_eval(err) != 0) {
    printk(KERN_INFO "ip_local_out() reported an error: %d\n", err);
  }

  return;
}

unsigned int lisp_output6(unsigned int hooknum,
			  struct sk_buff *packet_buf,
			  const struct net_device *input_dev,
			  const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*))
{
  struct ipv6hdr *iph;
  struct tcphdr *tcph;
  lisp_map_cache_t *eid_entry;
  int retval;
  lisp_addr_t locator_addr;
  unsigned char loc_index;
  ushort      loc_afi;
  lisp_addr_t dst_addr;

  /* 
   * Extract the ip header
   */
  iph = ipv6_hdr(packet_buf);
  
#ifdef DEBUG
  printk(KERN_INFO "   Output packet originally destined for %pI6 from %pI6\n", iph->daddr.s6_addr,
         iph->saddr.s6_addr);
#endif


  /*
   * Check for local destination, punt if so.
   * AL: An equivalent function to is_v4addr_local has not been found.
   *   : As the default route is through the interface lmn0, if the output interface is not lmn0 the packet
   *   : has a local destination.
   */

  if (strcmp(output_dev->name,LISP_EID_INTERFACE)!=0)
  {
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "       Packet is locally destined.\n");
#endif
      return NF_ACCEPT;
  }



  /*
   * Check whether the packet should be encapsulated
   */
  if(globals.num_local_eid>0){
	  if(!is_addrv6_local_eid(iph)){
#ifdef DEBUG_PACKETS
		  printk(KERN_INFO "       Packet src is not a local EID\n");
#endif
		  return NF_ACCEPT;
	  }
  }


  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Eventually, when supporting ipv6/ipv6 or v4 or v6, we
   * will need to escape LISP control messages, like in lisp_output4.
   * XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  memcpy(dst_addr.address.ipv6.s6_addr, iph->daddr.s6_addr, sizeof(lisp_addr_t));
  retval = lookup_eid_cache_v6(dst_addr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {

    printk(KERN_INFO "No EID mapping found, notifying lispd...\n");
    send_cache_miss_notification(dst_addr, AF_INET6);
    return NF_ACCEPT;  // What's the right thing to do here? XXX
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Get the first locator for now... sync up with output4 to use hash XXX
   */
  loc_index = eid_entry->locator_hash_table[output_hash_v6(iph->saddr, iph->daddr)];
  if (!eid_entry->locator_list[loc_index]) {
    printk(KERN_INFO " No suitable locators.\n");
    return(NF_DROP);
  } else {
      loc_afi = eid_entry->locator_list[loc_index]->locator.afi;
      memcpy(&locator_addr, &eid_entry->locator_list[loc_index]->locator, sizeof(lisp_addr_t));
      printk(KERN_INFO " Locator found.\n");
  }
  

  /*
   * We recalculate the checksum of the TCP packets to be encapsulated
   * Due to checksum offload the internal packets are sent with the wrong
   * checksum
   */

  if (iph->nexthdr == IPPROTO_TCP) {
      skb_pull(packet_buf, sizeof(struct ipv6hdr));
      skb_reset_transport_header(packet_buf);
      tcph = tcp_hdr(packet_buf);
      tcph->check=0;
      tcph->check = csum_ipv6_magic(&(iph->saddr), &(iph->daddr), packet_buf->len, IPPROTO_TCP, csum_partial((char *)tcph, packet_buf->len, 0));
      skb_push(packet_buf, sizeof(struct ipv6hdr));
  }

  /* 
   * Prepend UDP, LISP, outer IP header
   */
  if (loc_afi == AF_INET) {
      lisp_encap4(packet_buf, locator_addr.address.ip.s_addr,AF_INET6);
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "   Using locator address: %pI4\n", &locator_addr);
#endif
  } else {
      if (loc_afi == AF_INET6) {
          lisp_encap6(packet_buf, locator_addr, AF_INET6);
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "   Using locator address: %pI6\n", locator_addr.address.ipv6.s6_addr);
#endif
      }
  }

  eid_entry->locator_list[0]->data_packets_out++;

  /* 
   * In all liklihood we've disposed of the orignal skb
   * for size reasons. We must transmit it ourselves, and
   * force the upper-layers to conside it gone.
   */
  return NF_STOLEN;
}

/*
 * is_v4addr_local
 *
 * Perform a route lookup to determine if this address
 * belongs to us. See arp.c for comparable check.
 */
bool is_v4addr_local(struct iphdr *iph, const struct net_device *output_dev)
{
    struct flowi fl;
    struct rtable *rt;
    struct net_device *dev;

    if(output_dev == NULL) {
          printk(KERN_DEBUG "output_dev is NULL!");
          return 0;
    }

    memset(&fl, 0, sizeof(fl));
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
    fl.u.ip4.daddr = iph->daddr;
    fl.flowi_tos = RTO_ONLINK;
    rt = ip_route_output_key(dev_net(output_dev), &fl.u.ip4);
    if (IS_ERR(rt))
#else
    fl.fl4_dst = iph->daddr;
    fl.fl4_tos = RTO_ONLINK;
    if (ip_route_output_key(dev_net(output_dev), &rt, &fl))
#endif
        return 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
    dev = rt->dst.dev;
#else
    dev = rt->u.dst.dev;
#endif
    ip_rt_put(rt);
    if (!dev)
        return 0;

    // If we got anything, it's local
    return 1;
}

unsigned int lisp_output4(unsigned int hooknum,
			  struct sk_buff *packet_buf,
			  const struct net_device *input_dev,
			  const struct net_device *output_dev,
			  int (*okfunc)(struct sk_buff*))
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udh;
  lisp_map_cache_t *eid_entry;
  int retval;
  int locator_addr;
  unsigned char loc_index;
  ushort loc_afi;
  lisp_addr_t miss_addr;

  /* 
   * Extract the ip header
   */
  iph = ip_hdr(packet_buf);
  
#ifdef DEBUG_PACKETS
  printk(KERN_INFO "   Output packet destined for %pI4 from %pI4, proto: %d\n", &(iph->daddr),
         &(iph->saddr), iph->protocol);
#endif

  /*
   * Check for local destination, punt if so.
   */
  if (is_v4addr_local(iph, output_dev)) {
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "       Packet is locally destined.\n");
#endif
      return NF_ACCEPT;
  }

  /*
   * Check whether the packet should be encapsulated
   */
  if(globals.num_local_eid>0){
	  if(!is_addrv4_local_eid(iph)){
#ifdef DEBUG_PACKETS
		  printk(KERN_INFO "       Packet src is not a local EID\n");
#endif
		  return NF_ACCEPT;
	  }
  }

  /*
   * Don't encapsulate LISP control messages
   */
  if (iph->protocol == IPPROTO_UDP) {
      skb_pull(packet_buf, sizeof(struct iphdr));
      skb_reset_transport_header(packet_buf);
      udh = udp_hdr(packet_buf);

      /*
       * If either of the udp ports are the control port or data, allow
       * to go out natively. This is a quick way around the
       * route filter which rewrites the EID as the source address.
       */
      if ( (ntohs(udh->dest) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_CONTROL_PORT) ||
          (ntohs(udh->source) == LISP_ENCAP_PORT) ||
          (ntohs(udh->dest) == LISP_ENCAP_PORT) ) {

          // Undo the pull
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "      Packet looks like lisp control: dstprt %d, srcprt %d\n",
                 ntohs(udh->dest), ntohs(udh->source));
#endif
          skb_push(packet_buf, sizeof(struct iphdr));
          return NF_ACCEPT;
      } else {
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "       Packet not lisp control: dstprt %d, srcprt %d\n", ntohs(udh->dest),
                 ntohs(udh->source));
#endif
      }
       // Undo the pull
      skb_push(packet_buf, sizeof(struct iphdr));
    }

  /*
   * Sanity check the inner packet XXX
   */

  /*
   * Lookup the destination in the map-cache, this will
   * need to return the full entry in the future for all
   * the flags to be processed. TDB: Check for concurrency
   * issues with directly using the entry pointer here. May
   * need to lock it or make a copy (ick)
   */
  retval = lookup_eid_cache_v4(iph->daddr, &eid_entry);
  
  /*
   * Check status of returned entry XXX (requires extension
   * of above function).
   */
  if (retval == 0 || !eid_entry->count) {

    printk(KERN_INFO "        No EID mapping found, notifying lispd...\n");
    miss_addr.address.ip.s_addr = iph->daddr;
    send_cache_miss_notification(miss_addr, AF_INET);
    return NF_DROP;  // Don't try to natively transmit without a cache entry
  }

  /*
   * Mark that traffic has been received.
   */
  eid_entry->active_within_period = 1;

  /*
   * Hash to find the correct locator based on weight, priority, etc.
   */
  loc_index = eid_entry->locator_hash_table[output_hash_v4(iph->saddr, iph->daddr)];
  if (eid_entry->locator_list[loc_index]) {
      loc_afi = eid_entry->locator_list[loc_index]->locator.afi;
      locator_addr = eid_entry->locator_list[loc_index]->locator.address.ip.s_addr;
  } else {
      printk(KERN_INFO "    Invalid locator list!\n");
      return NF_ACCEPT;
  }


  /*
   * We recalculate the checksum of the TCP packets to be encapsulated
   * Due to checksum offload the internal packets are sent with the wrong
   * checksum
   */

   if (iph->protocol == IPPROTO_TCP) {
       skb_pull(packet_buf, sizeof(struct iphdr));
       skb_reset_transport_header(packet_buf);
       tcph = tcp_hdr(packet_buf);
       tcph->check=0;
       tcph->check = tcp_v4_check(packet_buf->len, iph->saddr, iph->daddr, csum_partial((char *)tcph, packet_buf->len, 0));
       skb_push(packet_buf, sizeof(struct iphdr));
  }

  /* 
   * Prepend UDP, LISP, outer IP header
   */
  if (loc_afi == AF_INET) {
      lisp_encap4(packet_buf, locator_addr, AF_INET);
#ifdef DEBUG_PACKETS
      printk(KERN_INFO "   Using locator address: %pI4\n", &locator_addr);
#endif
  } else {
      if (loc_afi == AF_INET6) {
          lisp_encap6(packet_buf, eid_entry->locator_list[loc_index]->locator, AF_INET);
#ifdef DEBUG_PACKETS
          printk(KERN_INFO "   Using locator address: %pI6\n", eid_entry->locator_list[loc_index]->locator.address.ipv6.s6_addr);
#endif
      }
  }

  eid_entry->locator_list[loc_index]->data_packets_out++;

#ifdef DEBUG_PACKETS
  printk(KERN_INFO "       Using locator address: %pI4\n", &locator_addr);
#endif

  /* 
   * In all liklihood we've disposed of the orignal skb
   * for size reasons. We must transmit it ourselves, and
   * force the upper-layers to conside it gone.
   */
  return NF_STOLEN;
}

