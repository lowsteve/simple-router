#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


static unsigned char BROADCAST[ETHER_ADDR_LEN];

struct sr_if * sr_ip_addressed_to_router(struct sr_instance * sr,uint8_t * packet);

/* ==< send routines >======================================================= */
/* =< send ethernet >======================================================== */
static void
sr_send_eth (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */,
    _Bool dofree)
{
  struct sr_arpentry * arpentry;
  struct sr_arpreq * arpreq;
  struct sr_if * iface;
  if(sr_get_eth_type(packet) == htons(ethertype_ip) /* IP */) {
    iface = sr_get_interface(sr, interface);
    sr_set_eth_shost(packet,iface->addr);
    arpentry = sr_arpcache_lookup(&(sr->cache),sr_get_ip_dst(packet));
    if(arpentry) {  /* arp cache hit */
      sr_set_eth_dhost(packet,(uint8_t *)arpentry->mac);
      free(arpentry);
    } else {        /* arp cache miss */
      arpreq = sr_arpcache_queuereq(&(sr->cache),
          sr_get_ip_dst(packet),
          packet,len,interface);
      free(packet);
      sr_handle_arpreq(sr,arpreq);
      return;
    }
  }

  if(sr_get_eth_type(packet) == htons(ethertype_arp) /* ARP */) {
    if(sr_get_arp_op(packet) == htons(arp_op_reply)) {
      sr_set_eth_dhost(packet,sr_get_arp_tha(packet));
      sr_set_eth_shost(packet,sr_get_arp_sha(packet));
    }
    if(sr_get_arp_op(packet) == htons(arp_op_request)) {
      sr_set_eth_dhost(packet,BROADCAST);
      sr_set_eth_shost(packet,sr_get_arp_sha(packet));
    }
  }
  sr_send_packet(sr,packet,len,interface);
  if(dofree) free(packet);
}
/* =< end send ethernet >=================================================== */
/* =< send ip >============================================================= */
static void
sr_send_ip (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */)
{
  struct sr_rt * route;
  struct sr_if * iface = sr_ip_addressed_to_router(sr,packet);

  if(iface == NULL) {  /* forward */
    route = sr_longest_prefix_match(sr,packet);
    if(route == NULL) {
      sr_send_icmp3(sr,packet,len,interface,icmp3_net);
      return;
    }
    interface = route->interface;
  } else {
    sr_set_ip_dst(packet,sr_get_ip_src(packet));
    sr_set_ip_src(packet,iface->ip);
  }

  sr_ip_dec_ttl(packet);

  sr_compute_set_ip_sum(packet);

  sr_set_eth_type(packet,htons(ethertype_ip));
  sr_send_eth(sr,packet,len,interface,1);
}
/* =< end send ip >========================================================== */
/* =< send imcp0 >=========================================================== */
static void
sr_send_icmp0 (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */)
{
  uint8_t * reply = sr_new_packet(len);
  memcpy(reply,packet,len);

  sr_set_icmp0_type(reply,0);
  sr_compute_set_icmp0_sum(reply,len);

  sr_cpy_hdr_ip(reply,packet);
  sr_set_ip_ttl(reply,101);

  sr_send_ip(sr,reply,len,interface);
}
/* =< end send icmp0 >======================================================= */
/* =< send imcp3 >=========================================================== */
void
sr_send_icmp3 (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */,
    uint8_t code)
{
  sr_validate_icmp3(packet,len);
  struct sr_if * iface = sr_get_interface(sr, interface);
  uint8_t * reply = sr_new_packet(ICMP3_LEN);

  sr_set_icmp3_type(reply,3);
  sr_set_icmp3_code(reply,code);
  sr_set_icmp3_data(reply,IP_HDR(packet));
  sr_compute_set_icmp3_sum(reply);

  /*sr_cpy_hdr_eth(reply,packet); */
  sr_cpy_hdr_ip(reply,packet);
  sr_set_ip_len(reply,htons(ICMP3_HDR_LEN + IP_HDR_LEN));
  sr_set_ip_id(reply,0);
  sr_set_ip_off(reply,htons(IP_DF));
  sr_set_ip_ttl(reply,101);
  sr_set_ip_p(reply,ip_protocol_icmp);

  if(code != 3) {
    sr_set_ip_dst(reply,sr_get_ip_src(packet));
    sr_set_ip_src(reply,iface->ip);
  }

  sr_send_ip(sr,reply,ICMP3_LEN,interface);
}
/* =< end send icmp3 >======================================================= */
/* =< send imcp11 >========================================================== */
static void
sr_send_icmp11 (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */)
{
  sr_validate_icmp11(packet,len);
  sr_set_ip_ttl(packet,sr_get_ip_ttl(packet) - 1);
  struct sr_if * iface = sr_get_interface(sr, interface);
  uint8_t * reply = sr_new_packet(ICMP11_LEN);

  sr_set_icmp11_type(reply,11);
  sr_set_icmp11_code(reply,0);
  sr_set_icmp11_data(reply,IP_HDR(packet));
  sr_compute_set_icmp11_sum(reply);

  sr_cpy_hdr_ip(reply,packet);
  sr_set_ip_len(reply,htons(ICMP11_HDR_LEN + IP_HDR_LEN));
  sr_set_ip_id(reply,0);
  sr_set_ip_off(reply,htons(IP_DF));
  sr_set_ip_ttl(reply,101);
  sr_set_ip_p(reply,ip_protocol_icmp);
  sr_set_ip_dst(reply,sr_get_ip_src(packet));
  sr_set_ip_src(reply,iface->ip);

  sr_send_ip(sr,reply,ICMP11_LEN,interface);
}
/* =< end send icmp11 >====================================================== */
/* =< send arp reply >======================================================= */
static void
sr_send_arp_reply (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */)
{
  struct sr_if * iface = sr_get_interface(sr, interface);
  assert(iface);
  uint8_t * reply = sr_new_packet(ETH_HDR_LEN + ARP_HDR_LEN);
  sr_cpy_hdr_arp(reply,packet);
  sr_set_arp_op(reply,htons(arp_op_reply));
  sr_set_arp_sha(reply,iface->addr);
  sr_set_arp_sip(reply,sr_get_arp_tip(packet));
  sr_set_arp_tha(reply,sr_get_arp_sha(packet));
  sr_set_arp_tip(reply,sr_get_arp_sip(packet));
  sr_set_eth_type(reply,htons(ethertype_arp));

  sr_send_eth(sr,reply,ETH_HDR_LEN+ARP_HDR_LEN,interface,1);
}
/* =< end send arp reply >=================================================== */
/* =< send arp request >===================================================== */
static void
sr_send_arp_request (struct sr_instance * sr,
    uint32_t ip,
    char * interface)
{
  struct sr_if * iface = sr_get_interface(sr,interface);
  uint8_t * request = sr_new_packet(ETH_HDR_LEN + ARP_HDR_LEN);

  sr_set_arp_hrd(request,htons(1));
  sr_set_arp_pro(request,htons(2048));
  sr_set_arp_hln(request,6);
  sr_set_arp_pln(request,4);
  sr_set_arp_op(request,htons(arp_op_request));
  sr_set_arp_sha(request,iface->addr);
  sr_set_arp_sip(request,iface->ip);
  sr_set_arp_tha(request,BROADCAST);
  sr_set_arp_tip(request,ip);
  sr_set_eth_type(request,htons(ethertype_arp));

  sr_send_eth(sr,request,ETH_HDR_LEN+ARP_HDR_LEN,interface,1);
}
/* =< end send arp request >================================================= */
/* =< send waiting arp reply  >============================================== */
static void
sr_send_waiting_arp_reply (struct sr_instance * sr,
    struct sr_arpreq * req,
    char * interface)
{
  struct sr_packet * list = req->packets;
  while(list) {
    sr_send_eth(sr,list->buf,list->len,list->iface,0);
    list=list->next;
  }
  sr_arpreq_destroy(&(sr->cache),req);
}
/* =< end send waiting arp reply  >========================================== */
/* ==< end send routines >=================================================== */


/* ==< forwarding  >========================================================= */
static void
sr_forward (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  if(sr_get_ip_ttl(packet) == 1) {
    sr_send_icmp11(sr,packet,len,interface);
    return;
  }

  uint8_t * forward = sr_new_packet(len);
  sr_cpy_packet(forward,packet,len);
  sr_send_ip(sr,forward,len,interface);
}
/* ==< end forwarding >====================================================== */


/* ==< recv routines >======================================================= */
/* =< recv arp >============================================================= */
static void
sr_recv_arp (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len,
  char * interface)
{
  struct sr_if * iface = sr_get_interface(sr, interface);
  if(sr_get_arp_tip(packet) != iface->ip)
    return;

  struct sr_arpentry * arpentry;
  struct sr_arpreq * arpreq;
  arpentry = sr_arpcache_lookup(&(sr->cache),sr_get_ip_src(packet));
  if(arpentry == NULL) {
    arpreq = sr_arpcache_insert(&(sr->cache),
        (unsigned char *)sr_get_arp_sha(packet),
        sr_get_arp_sip(packet));
    if(arpreq)
      sr_send_waiting_arp_reply(sr,arpreq,interface);
  } else {
    free(arpentry);
  }
  arpentry = NULL;
  arpreq = NULL;


  if(ntohs(sr_get_arp_op(packet)) == arp_op_request) {
    sr_send_arp_reply(sr,packet,len,interface);
    return;
  }
}
/* =< end recv arp >======================================================== */
/* =< recv udp >============================================================ */
static void
sr_recv_udp (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  if(sr_ip_addressed_to_router(sr,packet)) {
    sr_send_icmp3(sr,packet,len,interface,icmp3_port);
    return;
  }

  sr_forward(sr,packet,len,interface);
}
/* =< end recv udp >========================================================= */
/* =< recv tdp >============================================================= */
static void
sr_recv_tcp (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  if(sr_ip_addressed_to_router(sr,packet)) {
    if (sr->nat != NULL) {
      /* FIXME -- */
      if(strcmp(interface,NAT_EXTERNAL_IF) == 0) {
        if(sr_get_tcp_syn(packet) == 1
            && ntohs(sr_get_tcp_dst(packet)) > 1024)
          return;
      }
      /* -- FIXME */
    }
    sr_send_icmp3(sr,packet,len,interface,icmp3_port);
    return;
  }

  sr_forward(sr,packet,len,interface);
}
/* =< end recv tcp >========================================================= */
/* =< recv icmp >============================================================ */
static void
sr_recv_icmp (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  if(sr_validate_icmp(packet,len)) return;

  if(sr_ip_addressed_to_router(sr,packet)) {
    if(sr_get_icmp_type(packet) == 8) {
      sr_send_icmp0(sr,packet,len,interface);
      return;
    }
  }

  sr_forward(sr,packet,len,interface);
}
/* =< end recv icmp >======================================================== */
/* =< recv ip >============================================================== */
static void
sr_recv_ip (struct sr_instance * sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char * interface/* lent */)
{
  if(sr_validate_ip(packet,len)) return;

  if(sr_get_ip_p(packet) == ip_protocol_icmp) {
    sr_recv_icmp(sr,packet,len,interface);
    return;
  }

  if(sr_get_ip_p(packet) == ip_protocol_udp) {
    sr_recv_udp(sr,packet,len,interface);
    return;
  }

  if(sr_get_ip_p(packet) == ip_protocol_tcp) {
    sr_recv_tcp(sr,packet,len,interface);
    return;
  }

  return;
}
/* =< end recv ip >========================================================== */
/* =< recv etherenet >======================================================= */
static void
sr_recv_ethernet (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  sr_validate_ethernet(packet,len);

  uint16_t etht = ethertype(packet);

  if(etht == ethertype_ip /* IP */) {
    sr_recv_ip(sr,packet,len,interface);
    return;
  }

  if(etht == ethertype_arp /* ARP */ ) {
    sr_recv_arp(sr,packet,len,interface);
    return;
  }

  return;
}
/* =< end recv etherenet >=================================================== */
/* ==< end recv routines >=================================================== */


/* ==< public routines >===================================================== */
/* =< router constructor >=================================================== */
void sr_init(struct sr_instance * sr)
{
  assert(sr);

  sr_arpcache_init(&(sr->cache));
  sr->nat = NULL;

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
  memset(BROADCAST,-1,ETHER_ADDR_LEN);
}

void
sr_handle_arpreq (struct sr_instance * sr,
    struct sr_arpreq * req)
{
  time_t now = time(NULL);
  struct sr_packet * packet;
  if(difftime(now, req->sent) > 0.1) {
    if(req->times_sent > 4) { /* unreachable */
      packet = req->packets;
      while(packet) {
        sr_send_icmp3(sr,packet->buf,packet->len,packet->iface,icmp3_host);
        packet = packet->next;
      }
      sr_arpreq_destroy(&(sr->cache),req);
    } else {
      sr_send_arp_request(sr,req->ip,req->packets->iface);
      req->sent = now;
      req->times_sent += 1;
    }
  }
}
/* =< main entry >=========================================================== */
void
sr_handlepacket (struct sr_instance * sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char * interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  sr_recv_ethernet(sr,packet,len,interface);
}
/* ==< end public routines >================================================= */

