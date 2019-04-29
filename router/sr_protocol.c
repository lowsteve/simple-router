#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

uint8_t *
sr_new_packet(size_t len)
{
  uint8_t * p = malloc(len);
  assert(p);
  memset(p,'\0',len);
  return p;
}

void
sr_cpy_packet(uint8_t * dst, uint8_t * src, size_t len)
{
  memcpy(dst,src,len);
}

/* ==< is addressed to router >============================================== */

struct sr_if *
sr_ip_addressed_to_router (struct sr_instance * sr, uint8_t * packet)
{
  struct sr_if * iface = sr->if_list;
  uint32_t ip = sr_get_ip_dst(packet);
  while(iface) {
    if(iface->ip == ip)
      break;
    iface = iface->next;
  }

  return iface;
}

/* ==< validate packets routines >=========================================== */
_Bool
sr_validate_ethernet (uint8_t * packet, unsigned int len)
{
  if(len < ETH_LEN) return 1;
  return 0;
}
_Bool
sr_validate_ip (uint8_t * packet, unsigned int len)
{
  if(len < IP_LEN) return 1;
  if(ntohs(sr_get_ip_len(packet)) > IP_MAXPACKET) {
    fprintf(stderr,"[PACKET DROPPED] ip packet too large\n");
    return 1;
  }

  uint16_t checksum = sr_get_ip_sum(packet);
  sr_set_ip_sum(packet,0);
  if(checksum != cksum(IP_HDR(packet), sr_get_ip_hl(packet) * 4)) {
    fprintf(stderr,"[PACKET DROPPED] ip checksum failed\n");
    return 1;
  }
  sr_set_ip_sum(packet,checksum);

  return 0;
}
_Bool
sr_validate_icmp (uint8_t * packet, unsigned int len)
{
  if(len < ICMP_LEN) return 1;

  uint16_t checksum = sr_get_icmp_sum(packet);
  sr_set_icmp_sum(packet,0);
  if(checksum != cksum(ICMP_HDR(packet), len - ETH_HDR_LEN - IP_HDR_LEN)) {
    fprintf(stderr,"[PACKET DROPPED] icmp checksum failed\n");
    return 1;
  }
  sr_set_icmp_sum(packet,checksum);

  return 0;
}
_Bool
sr_validate_icmp3 (uint8_t * packet, unsigned int len)
{
  if(len < ICMP3_LEN) return 1;
  return 0;
}
_Bool
sr_validate_icmp11 (uint8_t * packet, unsigned int len)
{
  if(len < ICMP11_LEN) return 1;
  return 0;
}
_Bool
sr_validate_tcp (uint8_t * packet, unsigned int len)
{
  return 0; /* TODO */
}
_Bool
sr_validate_udp (uint8_t * packet, unsigned int len)
{
  return 0; /* TODO */
}

/* ==< compute and set checksums >=========================================== */
void
sr_compute_set_ip_sum (uint8_t * packet) {
  sr_set_ip_sum(packet,0);
  uint16_t checksum = cksum(IP_HDR(packet),IP_HDR_LEN);
  sr_set_ip_sum(packet,checksum);
}
void
sr_compute_set_icmp_sum (uint8_t * packet, size_t len) {
  sr_set_icmp_sum(packet,0);
  uint16_t checksum = cksum(ICMP_HDR(packet),len);
  sr_set_icmp_sum(packet,checksum);
}
void
sr_compute_set_icmp0_sum (uint8_t * packet, size_t len) {
  sr_compute_set_icmp_sum(packet,len - ETH_HDR_LEN - IP_HDR_LEN);
}
void
sr_compute_set_icmp3_sum (uint8_t * packet) {
  sr_compute_set_icmp_sum(packet,ICMP3_HDR_LEN);
}
void
sr_compute_set_icmp8_sum (uint8_t * packet) {
  sr_compute_set_icmp_sum(packet,ICMP8_HDR_LEN);
}
void
sr_compute_set_icmp11_sum (uint8_t * packet) {
  sr_compute_set_icmp_sum(packet,ICMP11_HDR_LEN);
}
void
sr_compute_set_tcp_sum (uint8_t * packet) {
  uint16_t tcp_data_len = sr_get_tcp_data_len(packet);
  uint16_t total_len = TCP_PSEUDO_HDR_LEN + tcp_data_len;
  uint8_t * tcp_pseudo_header  = alloca(total_len);

  sr_set_tcp_pseudo_header(packet,tcp_pseudo_header);
  sr_cpy_tcp_data(packet,tcp_pseudo_header + TCP_PSEUDO_HDR_LEN);

  uint16_t checksum = cksum(tcp_pseudo_header,total_len);
  sr_set_tcp_sum(packet,checksum);
}
/* ==< header copy routines >================================================ */
void
sr_cpy_hdr_ip(uint8_t * d, uint8_t * s)
{
  memcpy(IP_HDR(d),IP_HDR(s),IP_HDR_LEN);
}
void
sr_cpy_hdr_eth(uint8_t * d, uint8_t * s)
{
  memcpy(ETH_HDR(d),ETH_HDR(s),ETH_HDR_LEN);
}
void
sr_cpy_hdr_icmp(uint8_t * d, uint8_t * s)
{
  memcpy(ICMP_HDR(d),ICMP_HDR(s),ICMP_HDR_LEN);
}
void
sr_cpy_hdr_arp(uint8_t * d, uint8_t * s)
{
  memcpy(ARP_HDR(d),ARP_HDR(s),ARP_HDR_LEN);
}

/* ==< icmp >================================================================ */
/* =< set >================================================================== */
void
sr_set_icmp_type (uint8_t * hdr, uint8_t type)
{
  ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN  + IP_HDR_LEN))->icmp_type = type;
}
void
sr_set_icmp_code (uint8_t * hdr, uint8_t code)
{
  ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN + IP_HDR_LEN))->icmp_code = code;
}
void
sr_set_icmp_sum (uint8_t * hdr, uint16_t sum)
{
  ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN + IP_HDR_LEN))->icmp_sum = sum;
}
/* =< get >================================================================== */
uint8_t
sr_get_icmp_type (uint8_t * hdr)
{
  return ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN  + IP_HDR_LEN))->icmp_type;
}
uint8_t
sr_get_icmp_code (uint8_t * hdr)
{
  return ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN + IP_HDR_LEN))->icmp_code;
}
uint16_t
sr_get_icmp_sum (uint8_t * hdr)
{
  return ((sr_icmp_hdr_t *) (hdr + ETH_HDR_LEN + IP_HDR_LEN))->icmp_sum;
}
/* ==< icmp end >============================================================ */



/* ==< icmp0 >=============================================================== */
/* =< set >================================================================== */
void
sr_set_icmp0_type (uint8_t * p, uint8_t icmp_type)
{
  ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_type = icmp_type;
}
void
sr_set_icmp0_code (uint8_t * p, uint8_t icmp_code)
{
  ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_code = icmp_code;
}
void
sr_set_icmp0_sum (uint8_t * p, uint16_t icmp_sum)
{
  ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_sum = icmp_sum;
}
void
sr_set_icmp0_id (uint8_t * p, uint16_t icmp_id)
{
  ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_id = icmp_id;
}
void
sr_set_icmp0_seq (uint8_t * p, uint16_t icmp_seq)
{
  ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_seq = icmp_seq;
}
/* =< get >================================================================== */
uint8_t
sr_get_icmp0_type (uint8_t * p)
{
  return ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_type;
}
uint8_t
sr_get_icmp0_code (uint8_t * p)
{
  return ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_code;
}
uint16_t
sr_get_icmp0_sum (uint8_t * p)
{
  return ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_sum;
}
uint16_t
sr_get_icmp0_id (uint8_t * p)
{
  return ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_id;
}
uint16_t
sr_get_icmp0_seq (uint8_t * p)
{
  return ((sr_icmp_t0_hdr_t *) (ICMP0_HDR(p)))->icmp_seq;
}
/* ==< end icmp0 >=========================================================== */

/* ==< icmp3 >=============================================================== */
/* =< set >================================================================== */
void
sr_set_icmp3_type (uint8_t * p, uint8_t icmp_type)
{
  ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_type = icmp_type;
}
void
sr_set_icmp3_code (uint8_t * p, uint8_t icmp_code)
{
  ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_code = icmp_code;
}
void
sr_set_icmp3_sum (uint8_t * p, uint16_t icmp_sum)
{
  ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_sum = icmp_sum;
}
void
sr_set_icmp3_unused (uint8_t * p, uint16_t unused)
{
  ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->unused = unused;
}
void
sr_set_icmp3_mtu (uint8_t * p, uint16_t next_mtu)
{
  ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->next_mtu = next_mtu;
}
void
sr_set_icmp3_data (uint8_t * p, uint8_t * data)
{
  memcpy(((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->data,data,ICMP_DATA_SIZE);
}
/* =< get >================================================================== */
uint8_t
sr_get_icmp3_type (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_type;
}
uint8_t
sr_get_icmp3_code (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_code;
}
uint16_t
sr_get_icmp3_sum (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->icmp_sum;
}
uint16_t
sr_get_icmp3_unused (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->unused;
}
uint16_t
sr_get_icmp3_mtu (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->next_mtu;
}
uint8_t *
sr_get_icmp3_data (uint8_t * p)
{
  return ((sr_icmp_t3_hdr_t *) (ICMP3_HDR(p)))->data;
}
/* ==< end icmp3 >=========================================================== */

/* ==< icmp8 >=============================================================== */
/* =< set >================================================================== */
void
sr_set_icmp8_type (uint8_t * p, uint8_t icmp_type)
{
  ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_type = icmp_type;
}
void
sr_set_icmp8_code (uint8_t * p, uint8_t icmp_code)
{
  ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_code = icmp_code;
}
void
sr_set_icmp8_sum (uint8_t * p, uint16_t icmp_sum)
{
  ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_sum = icmp_sum;
}
void
sr_set_icmp8_id (uint8_t * p, uint16_t icmp_id)
{
  ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_id = icmp_id;
}
void
sr_set_icmp8_seq (uint8_t * p, uint16_t icmp_seq)
{
  ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_seq = icmp_seq;
}
/* =< get >================================================================== */
uint8_t
sr_get_icmp8_type (uint8_t * p)
{
  return ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_type;
}
uint8_t
sr_get_icmp8_code (uint8_t * p)
{
  return ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_code;
}
uint16_t
sr_get_icmp8_sum (uint8_t * p)
{
  return ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_sum;
}
uint16_t
sr_get_icmp8_id (uint8_t * p)
{
  return ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_id;
}
uint16_t
sr_get_icmp8_seq (uint8_t * p)
{
  return ((sr_icmp_t8_hdr_t *) (ICMP8_HDR(p)))->icmp_seq;
}
/* ==< end icmp8 >=========================================================== */


/* ==< icmp11 >============================================================== */
/* =< set >================================================================== */
void
sr_set_icmp11_type (uint8_t * p, uint8_t icmp_type)
{
  ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_type = icmp_type;
}
void
sr_set_icmp11_code (uint8_t * p, uint8_t icmp_code)
{
  ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_code = icmp_code;
}
void
sr_set_icmp11_sum (uint8_t * p, uint16_t icmp_sum)
{
  ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_sum = icmp_sum;
}
void
sr_set_icmp11_unused (uint8_t * p, uint32_t unused)
{
  ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->unused = unused;
}
void
sr_set_icmp11_data (uint8_t * p, uint8_t * data)
{
  memcpy(((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->data,data,ICMP_DATA_SIZE);
}
/* =< get >================================================================== */
uint8_t
sr_get_icmp11_type (uint8_t * p)
{
  return ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_type;
}
uint8_t
sr_get_icmp11_code (uint8_t * p)
{
  return ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_code;
}
uint16_t
sr_get_icmp11_sum (uint8_t * p)
{
  return ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->icmp_sum;
}
uint32_t
sr_get_icmp11_unused (uint8_t * p)
{
  return ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->unused;
}
uint8_t *
sr_get_icmp11_data (uint8_t * p)
{
  return ((sr_icmp_t11_hdr_t *) (ICMP11_HDR(p)))->data;
}
/* ==< end icmp11 >========================================================== */


/* ==< udp >================================================================= */
/* =< set >================================================================== */
void
sr_set_udp_src (uint8_t * p, uint16_t udp_src)
{
  ((sr_udp_hdr_t*) (UDP_HDR(p)))->udp_src = udp_src;
}
void
sr_set_udp_dst (uint8_t * p, uint16_t udp_dst)
{
  ((sr_udp_hdr_t*) (UDP_HDR(p)))->udp_src = udp_dst;
}
void
sr_set_udp_len (uint8_t * p, uint16_t udp_len)
{
  ((sr_udp_hdr_t*) (UDP_HDR(p)))->udp_len = udp_len;
}
void
sr_set_udp_sum (uint8_t * p, uint16_t udp_sum)
{
  ((sr_udp_hdr_t*) (UDP_HDR(p)))->udp_sum = udp_sum;
}
/* =< get >================================================================== */
uint16_t
sr_get_udp_src (uint8_t * p)
{
  return ((sr_udp_hdr_t *) (UDP_HDR(p)))->udp_src;
}
uint16_t
sr_get_udp_dst (uint8_t * p)
{
  return ((sr_udp_hdr_t *) (UDP_HDR(p)))->udp_dst;
}
uint16_t
sr_get_udp_len (uint8_t * p)
{
  return ((sr_udp_hdr_t *) (UDP_HDR(p)))->udp_len;
}
uint16_t
sr_get_udp_sum (uint8_t * p)
{
  return ((sr_udp_hdr_t *) (UDP_HDR(p)))->udp_sum;
}
/* ==< end udp >============================================================= */


/* ==< tcp >================================================================= */
/* =< set >================================================================== */
void
sr_set_tcp_src (uint8_t * p, uint16_t tcp_src)
{
  ((sr_tcp_hdr_t*) (TCP_HDR(p)))->tcp_src = tcp_src;
}
void
sr_set_tcp_dst (uint8_t * p, uint16_t tcp_dst)
{
  ((sr_tcp_hdr_t*) (TCP_HDR(p)))->tcp_src = tcp_dst;
}
void
sr_set_tcp_hl (uint8_t * p, uint8_t tcp_hl)
{
  ((sr_tcp_hdr_t*) (TCP_HDR(p)))->tcp_hl = tcp_hl;
}
void
sr_set_tcp_syn (uint8_t * p, uint8_t tcp_syn)
{
  ((sr_tcp_hdr_t*) (TCP_HDR(p)))->tcp_hl = tcp_syn;
}
void
sr_set_tcp_sum (uint8_t * p, uint16_t tcp_sum)
{
  ((sr_tcp_hdr_t*) (TCP_HDR(p)))->tcp_sum = tcp_sum;
}
/* =< get >================================================================== */
uint16_t
sr_get_tcp_src (uint8_t * p)
{
  return ((sr_tcp_hdr_t *) (TCP_HDR(p)))->tcp_src;
}
uint16_t
sr_get_tcp_dst (uint8_t * p)
{
  return ((sr_tcp_hdr_t *) (TCP_HDR(p)))->tcp_dst;
}
uint8_t
sr_get_tcp_hl (uint8_t * p)
{
  return ((sr_tcp_hdr_t *) (TCP_HDR(p)))->tcp_hl;
}
uint8_t
sr_get_tcp_syn (uint8_t * p)
{
  return ((sr_tcp_hdr_t *) (TCP_HDR(p)))->tcp_syn;
}
uint16_t
sr_get_tcp_sum (uint8_t * p)
{
  return ((sr_tcp_hdr_t *) (TCP_HDR(p)))->tcp_sum;
}
uint8_t *
sr_get_tcp_data (uint8_t * p) {
  uint16_t tcp_hl = sr_get_tcp_hl(p) * 4;
  return TCP_HDR(p) + tcp_hl;
}
/* =< misc >================================================================= */
uint16_t
sr_get_tcp_data_len (uint8_t * p)
{
  uint16_t ip_len = sr_get_ip_len(p);
  uint8_t  ip_hl  = sr_get_ip_hl(p);
  uint8_t tcp_hl  = sr_get_tcp_hl(p);
  return ip_len - (ip_hl + tcp_hl) * 4;
}
void
sr_set_tcp_pseudo_header (uint8_t * p, uint8_t * q)
{
  sr_tcp_pseudo_hdr_t * h =  (sr_tcp_pseudo_hdr_t * ) q;
  h->u32[0] = sr_get_ip_src(p);
  h->u32[1] = sr_get_ip_dst(p);
  h->u8[8]  = 0;
  h->u8[9]  = sr_get_ip_p(p);
  h->u16[5] = sr_get_ip_len(p);
}
void
sr_cpy_tcp_data (uint8_t * src, uint8_t * dst)
{
  uint16_t tcp_data_len = sr_get_tcp_data_len(src);
  memcpy(dst,sr_get_tcp_data(src),tcp_data_len);
}
/* ==< end udp >============================================================= */


/* ==< ip >================================================================== */
/* =< set >================================================================== */
void
sr_set_ip_hl(uint8_t * p, unsigned char ip_hl)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_hl = ip_hl;
}
void
sr_set_ip_v(uint8_t * p, unsigned char ip_v)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_v = ip_v;
}
void
sr_set_ip_tos(uint8_t * p, uint8_t ip_tos)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_tos = ip_tos;
}
void
sr_set_ip_len(uint8_t * p, uint16_t ip_len)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_len = ip_len;
}
void
sr_set_ip_id(uint8_t * p, uint16_t ip_id)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_id = ip_id;
}
void
sr_set_ip_off(uint8_t * p, uint16_t ip_off)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_off = ip_off;
}
void
sr_set_ip_ttl(uint8_t * p, uint8_t ip_ttl)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_ttl = ip_ttl;
}
void
sr_set_ip_p(uint8_t * p, uint8_t ip_p)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_p = ip_p;
}
void
sr_set_ip_sum(uint8_t * p, uint16_t ip_sum)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_sum = ip_sum;
}
void
sr_set_ip_src(uint8_t * p, uint32_t ip_src)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_src = ip_src;
}
void
sr_set_ip_dst(uint8_t * p, uint32_t ip_dst)
{
  ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_dst = ip_dst;
}
/* =< get >================================================================== */
unsigned char
sr_get_ip_hl(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_hl;
}
unsigned char
sr_get_ip_v(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_v;
}
uint8_t
sr_get_ip_tos(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_tos;
}
uint16_t
sr_get_ip_len(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_len;
}
uint16_t
sr_get_ip_id(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_id;
}
uint16_t
sr_get_ip_off(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_off;
}
uint8_t
sr_get_ip_ttl(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_ttl;
}
uint8_t
sr_get_ip_p(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_p;
}
uint16_t
sr_get_ip_sum(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_sum;
}
uint32_t
sr_get_ip_src(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_src;
}
uint32_t
sr_get_ip_dst(uint8_t * p)
{
  return ((sr_ip_hdr_t*) (IP_HDR(p)))->ip_dst;
}
/* =< misc >================================================================= */
void
sr_ip_dec_ttl(uint8_t * packet)
{
  sr_set_ip_ttl(packet,sr_get_ip_ttl(packet)-1);
}
/* ==< end ip >============================================================== */


/* ==< ethernet >============================================================ */
/* =< set >================================================================== */
void
sr_set_eth_dhost(uint8_t * p, uint8_t * ether_dhost)
{
  memcpy(((sr_ethernet_hdr_t *) p)->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
}
void
sr_set_eth_shost(uint8_t * p, uint8_t * ether_shost)
{
  memcpy(((sr_ethernet_hdr_t *) p)->ether_shost,ether_shost,ETHER_ADDR_LEN);
}
void
sr_set_eth_type(uint8_t * p, uint16_t ether_type)
{
  ((sr_ethernet_hdr_t *) p)->ether_type = ether_type;
}
/* =< get >================================================================== */
uint8_t *
sr_get_eth_dhost(uint8_t * p)
{
  return ((sr_ethernet_hdr_t *) p)->ether_dhost;
}
uint8_t *
sr_get_eth_shost(uint8_t * p)
{
  return ((sr_ethernet_hdr_t *) p)->ether_shost;
}
uint16_t
sr_get_eth_type(uint8_t * p)
{
  return ((sr_ethernet_hdr_t *) p)->ether_type;
}
/* ==< end ethernet >======================================================== */


/* ==< arp >================================================================= */
/* =< set >================================================================== */
void
sr_set_arp_hrd (uint8_t * hdr, unsigned short hrd)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_hrd = hrd;
}
void
sr_set_arp_pro (uint8_t * hdr, unsigned short pro)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_pro = pro;
}
void
sr_set_arp_hln (uint8_t * hdr, unsigned short hln)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_hln = hln;
}
void
sr_set_arp_pln (uint8_t * hdr, unsigned short pln)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_pln = pln;
}
void
sr_set_arp_op (uint8_t * hdr, unsigned short op)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_op = op;
}
void
sr_set_arp_sha (uint8_t * hdr, unsigned char * sha)
{
  unsigned char * dest_sha =((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_sha;
  memcpy(dest_sha,sha,ETHER_ADDR_LEN);
}
void
sr_set_arp_sip (uint8_t * hdr, uint32_t sip)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_sip = sip;
}
void
sr_set_arp_tha (uint8_t * hdr, unsigned char * tha)
{
  unsigned char * dest_tha =((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_tha;
  memcpy(dest_tha,tha,ETHER_ADDR_LEN);
}
void
sr_set_arp_tip (uint8_t * hdr, uint32_t tip)
{
  ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_tip = tip;
}
/* =< end >================================================================== */
unsigned short
sr_get_arp_hrd (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_hrd;
}
unsigned short
sr_get_arp_pro (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_pro;
}
unsigned char
sr_get_arp_hln (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_hln;
}
unsigned char
sr_get_arp_pln (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_pln;
}
unsigned short
sr_get_arp_op (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_op;
}
unsigned char *
sr_get_arp_sha (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_sha;
}
uint32_t
sr_get_arp_sip (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_sip;
}
unsigned char *
sr_get_arp_tha (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_tha;
}
uint32_t
sr_get_arp_tip (uint8_t * hdr)
{
  return ((sr_arp_hdr_t *) (hdr + ETH_HDR_LEN))->ar_tip;
}
/* ==< end arp >============================================================= */

