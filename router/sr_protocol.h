/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_                                                             */

#include <sys/types.h>
#include <arpa/inet.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif


#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif

/* ==< defines >============================================================= */

/* =< header lengths >======================================================= */
#define ETH_HDR_LEN         14
#define ARP_HDR_LEN         28
#define IP_HDR_LEN          20
#define ICMP_HDR_LEN        4
#define ICMP0_HDR_LEN       8
#define ICMP3_HDR_LEN       36
#define ICMP8_HDR_LEN       8
#define ICMP11_HDR_LEN      36
#define UDP_HDR_LEN         8
#define TCP_HDR_LEN         40
#define TCP_PSEUDO_HDR_LEN  12

/* =< min messages sizes >=================================================== */
#define ETH_LEN       ETH_HDR_LEN
#define IP_LEN        ETH_HDR_LEN + IP_HDR_LEN
#define ICMP_LEN      ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN
#define ICMP0_LEN     ETH_HDR_LEN + IP_HDR_LEN + ICMP0_HDR_LEN
#define ICMP3_LEN     ETH_HDR_LEN + IP_HDR_LEN + ICMP3_HDR_LEN
#define ICMP8_LEN     ETH_HDR_LEN + IP_HDR_LEN + ICMP8_HDR_LEN
#define ICMP11_LEN    ETH_HDR_LEN + IP_HDR_LEN + ICMP11_HDR_LEN
#define UPD_LEN       EHT_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN
#define TCP_LEN       ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN

/* =< base pointer to header pointer conversions >=========================== */
#define ICMP_HDR(x)   ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define ICMP0_HDR(x)  ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define ICMP3_HDR(x)  ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define ICMP8_HDR(x)  ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define ICMP11_HDR(x) ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define UDP_HDR(x)    ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define TCP_HDR(x)    ( (x) + ETH_HDR_LEN + IP_HDR_LEN )
#define ARP_HDR(x)    ( (x) + ETH_HDR_LEN )
#define IP_HDR(x)     ( (x) + ETH_HDR_LEN )
#define ETH_HDR(x)    ( (x) )

/* =< limits >=============================================================== */
#define sr_IFACE_NAMELEN  32
#define ICMP_DATA_SIZE    28

/* ==< end defines >========================================================= */

/* ==< icmp types >========================================================== */
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_REPLY    0
/* ==< end icmp types >====================================================== */

/* ==< packet management >=================================================== */
uint8_t * sr_new_packet (size_t len);
void sr_cpy_packet      (uint8_t * dst, uint8_t * src, size_t len);
/* ==< end packet management >=============================================== */

/* ==< header copy routines >================================================ */
uint8_t * sr_new_packet (size_t len);
void sr_cpy_hdr_ip      (uint8_t * d, uint8_t * s);
void sr_cpy_hdr_eth     (uint8_t * d, uint8_t * s);
void sr_cpy_hdr_icmp    (uint8_t * d, uint8_t * s);
void sr_cpy_hdr_arp     (uint8_t * d, uint8_t * s);
/* ==< end header copy routines >============================================ */

/* ==< validation routines >================================================= */
_Bool sr_validate_ethernet  (uint8_t * packet,unsigned int len);
_Bool sr_validate_ip        (uint8_t * packet, unsigned int len);
_Bool sr_validate_icmp      (uint8_t * packet, unsigned int len);
_Bool sr_validate_icmp3     (uint8_t * packet, unsigned int len);
_Bool sr_validate_icmp11    (uint8_t * packet, unsigned int len);
_Bool sr_validate_tcp       (uint8_t * packet, unsigned int len);
_Bool sr_validate_udp       (uint8_t * packet, unsigned int len);
/* ==< end validation routines >============================================= */

/* ==< compute and set icmp checksums >====================================== */
void sr_compute_set_icmp0_sum  (uint8_t * p, size_t len);
void sr_compute_set_icmp3_sum  (uint8_t * p);
void sr_compute_set_icmp8_sum  (uint8_t * p);
void sr_compute_set_icmp11_sum (uint8_t * p);
void sr_compute_set_ip_sum     (uint8_t * p);
void sr_compute_set_tcp_sum    (uint8_t * p);
/* ==< end compute and set icmp checksums >================================== */

/* ==< icmp header >========================================================= */
struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;

} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;
/* =< icmp set routines >==================================================== */
void sr_set_icmp_type     (uint8_t * hdr, uint8_t type);
void sr_set_icmp_code     (uint8_t * hdr, uint8_t code);
void sr_set_icmp_sum      (uint8_t * hdr, uint16_t sum);
/* =< icmp get routines >==================================================== */
uint8_t sr_get_icmp_type  (uint8_t * hdr);
uint8_t sr_get_icmp_code  (uint8_t * hdr);
uint16_t sr_get_icmp_sum  (uint8_t * hdr);
/* ==< icmp header end >===================================================== */



/* ==< icmp type 0 header >================================================== */
struct sr_icmp_t0_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t icmp_id;
  uint16_t icmp_seq;

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t0_hdr sr_icmp_t0_hdr_t;
/* =< icmp type 0 set routines >============================================= */
void sr_set_icmp0_type        (uint8_t * p, uint8_t icmp_type);
void sr_set_icmp0_code        (uint8_t * p, uint8_t icmp_code);
void sr_set_icmp0_sum         (uint8_t * p, uint16_t icmp_sum);
void sr_set_icmp0_id          (uint8_t * p, uint16_t id);
void sr_set_icmp0_seq         (uint8_t * p, uint16_t seq);
/* =< icmp type 0 get routines >============================================= */
uint8_t sr_get_icmp0_type     (uint8_t * p);
uint8_t sr_get_icmp0_code     (uint8_t * p);
uint16_t sr_get_icmp0_sum     (uint8_t * p);
uint16_t sr_get_icmp0_id      (uint8_t * p);
uint16_t sr_get_icmp0_seq     (uint8_t * p);
/* ==< end icmp type 0 header >============================================== */


/* ==< icmp type 3 header >================================================== */
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;
/* =< icmp type 3 set routines >============================================= */
void sr_set_icmp3_type        (uint8_t * p, uint8_t icmp_type);
void sr_set_icmp3_code        (uint8_t * p, uint8_t icmp_code);
void sr_set_icmp3_sum         (uint8_t * p, uint16_t icmp_sum);
void sr_set_icmp3_unused      (uint8_t * p, uint16_t unused);
void sr_set_icmp3_mtu         (uint8_t * p, uint16_t next_mtu);
void sr_set_icmp3_data        (uint8_t * p, uint8_t * data);
/* =< icmp type 3 get routines >============================================= */
uint8_t sr_get_icmp3_type     (uint8_t * p);
uint8_t sr_get_icmp3_code     (uint8_t * p);
uint16_t sr_get_icmp3_sum     (uint8_t * p);
uint16_t sr_get_icmp3_unused  (uint8_t * p);
uint16_t sr_get_icmp3_mtu     (uint8_t * p);
uint8_t * sr_get_icmp3_data   (uint8_t * p);
/* ==< end icmp type 3 header >============================================== */

/* ==< icmp type 8 header >================================================== */
struct sr_icmp_t8_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t icmp_id;
  uint16_t icmp_seq;

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t8_hdr sr_icmp_t8_hdr_t;
/* =< icmp type 8 set routines >============================================= */
void sr_set_icmp8_type        (uint8_t * p, uint8_t icmp_type);
void sr_set_icmp8_code        (uint8_t * p, uint8_t icmp_code);
void sr_set_icmp8_sum         (uint8_t * p, uint16_t icmp_sum);
void sr_set_icmp8_id          (uint8_t * p, uint16_t id);
void sr_set_icmp8_seq         (uint8_t * p, uint16_t seq);
/* =< icmp type 8 get routines >============================================= */
uint8_t sr_get_icmp8_type     (uint8_t * p);
uint8_t sr_get_icmp8_code     (uint8_t * p);
uint16_t sr_get_icmp8_sum     (uint8_t * p);
uint16_t sr_get_icmp8_id      (uint8_t * p);
uint16_t sr_get_icmp8_seq     (uint8_t * p);
/* ==< end icmp type 8 header >============================================== */

/* ==< icmp type 11 header >================================================= */
struct sr_icmp_t11_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint32_t unused;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t11_hdr sr_icmp_t11_hdr_t;
/* =< icmp type 11 set routines >============================================ */
void sr_set_icmp11_type         (uint8_t * p, uint8_t icmp_type);
void sr_set_icmp11_code         (uint8_t * p, uint8_t icmp_code);
void sr_set_icmp11_sum          (uint8_t * p, uint16_t icmp_sum);
void sr_set_icmp11_unused       (uint8_t * p, uint32_t unused);
void sr_set_icmp11_data         (uint8_t * p, uint8_t * data);
/* =< icmp type 11 get routines >============================================ */
uint8_t sr_get_icmp11_type      (uint8_t * p);
uint8_t sr_get_icmp11_code      (uint8_t * p);
uint16_t sr_get_icmp11_sum      (uint8_t * p);
uint32_t sr_get_icmp11_unused   (uint8_t * p);
uint8_t * sr_get_icmp11_data    (uint8_t * p);
/* ==< end icmp type 11 header >============================================= */

/* ==< ip header >=========================================================== */
struct sr_ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		  /* header length                                */
    unsigned int ip_v:4;		  /* version                                      */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		  /* version                                      */
    unsigned int ip_hl:4;		  /* header length                                */
#else
#error "Byte ordering ot specified "
#endif
    uint8_t ip_tos;			      /* type of service                              */
    uint16_t ip_len;			    /* total length                                 */
    uint16_t ip_id;			      /* identification                               */
    uint16_t ip_off;			    /* fragment offset field                        */
#define	IP_RF 0x8000			    /* reserved fragment flag                       */
#define	IP_DF 0x4000			    /* dont fragment flag                           */
#define	IP_MF 0x2000			    /* more fragments flag                          */
#define	IP_OFFMASK 0x1fff		  /* mask for fragmenting bits                    */
    uint8_t ip_ttl;			      /* time to live                                 */
    uint8_t ip_p;			        /* protocol                                     */
    uint16_t ip_sum;			    /* checksum                                     */
    uint32_t ip_src, ip_dst;	/* source and dest address                      */
  } __attribute__ ((packed)) ;
typedef struct sr_ip_hdr sr_ip_hdr_t;
/* =< ip set routines >====================================================== */
void sr_set_ip_hl           (uint8_t * p, unsigned char ip_hl);
void sr_set_ip_v            (uint8_t * p, unsigned char ip_v);
void sr_set_ip_tos          (uint8_t * p, uint8_t ip_tos);
void sr_set_ip_len          (uint8_t * p, uint16_t ip_len);
void sr_set_ip_id           (uint8_t * p, uint16_t ip_id);
void sr_set_ip_off          (uint8_t * p, uint16_t ip_off);
void sr_set_ip_ttl          (uint8_t * p, uint8_t ip_ttl);
void sr_set_ip_p            (uint8_t * p, uint8_t ip_p);
void sr_set_ip_sum          (uint8_t * p, uint16_t ip_sum);
void sr_set_ip_src          (uint8_t * p, uint32_t ip_src);
void sr_set_ip_dst          (uint8_t * p, uint32_t ip_dst);
unsigned char sr_get_ip_hl  (uint8_t * p);
unsigned char sr_get_ip_v   (uint8_t * p);
/* =< ip get routines >====================================================== */
uint8_t sr_get_ip_tos       (uint8_t * p);
uint16_t sr_get_ip_len      (uint8_t * p);
uint16_t sr_get_ip_id       (uint8_t * p);
uint16_t sr_get_ip_off      (uint8_t * p);
uint8_t sr_get_ip_ttl       (uint8_t * p);
uint8_t sr_get_ip_p         (uint8_t * p);
uint16_t sr_get_ip_sum      (uint8_t * p);
uint32_t sr_get_ip_src      (uint8_t * p);
uint32_t sr_get_ip_dst      (uint8_t * p);
/* =< ip misc routines >===================================================== */
void sr_ip_dec_ttl          (uint8_t * p);
/* ==< end ip header >======================================================= */

/* ==< tcp header >========================================================== */
struct sr_tcp_hdr {
  uint16_t tcp_src;
  uint16_t tcp_dst;
  uint32_t tcp_seq_num;
  uint32_t tcp_ack_num;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t tcp_res1:4;
  uint8_t tcp_hl:4;
  uint8_t tcp_fin:1;
  uint8_t tcp_syn:1;
  uint8_t tcp_rst:1;
  uint8_t tcp_psh:1;
  uint8_t tcp_ack:1;
  uint8_t tcp_urg:1;
  uint8_t tcp_res2:2;
#else
  uint8_t tcp_hl:4;
  uint8_t tcp_res:6;
  uint8_t tcp_urg:1;
  uint8_t tcp_ack:1;
  uint8_t tcp_psh:1;
  uint8_t tcp_rst:1;
  uint8_t tcp_syn:1;
  uint8_t tcp_fin:1;
#endif
  uint8_t  tcp_win_size;
  uint16_t tcp_sum;
  uint16_t tcp_urg_ptr;
} __attribute__ ((packed));
typedef struct sr_tcp_hdr sr_tcp_hdr_t;
/* =< tcp set routines >===================================================== */
void sr_set_tcp_src           (uint8_t * p, uint16_t tcp_src);
void sr_set_tcp_dst           (uint8_t * p, uint16_t tcp_dst);
void sr_set_tcp_hl            (uint8_t * p, uint8_t tcp_hl);
void sr_set_tcp_syn           (uint8_t * p, uint8_t tcp_syn);
void sr_set_tcp_sum           (uint8_t * p, uint16_t tcp_sum);
/* =< tcp get routines >===================================================== */
uint16_t sr_get_tcp_src       (uint8_t * p);
uint16_t sr_get_tcp_dst       (uint8_t * p);
uint8_t sr_get_tcp_hl         (uint8_t * p);
uint8_t sr_get_tcp_syn        (uint8_t * p);
uint16_t sr_get_tcp_sum       (uint8_t * p);
uint8_t * sr_get_tcp_data     (uint8_t * p);
/* =< tcp misc routines >==================================================== */
uint16_t sr_get_tcp_data_len  (uint8_t * p);
void sr_set_tcp_pseudo_header (uint8_t * p, uint8_t * q);
void sr_cpy_tcp_data          (uint8_t * src, uint8_t * dst);
/* ==< end tcp header >====================================================== */

/* ==< udp header >========================================================== */
struct sr_udp_hdr {
  uint16_t udp_src;
  uint16_t udp_dst;
  uint16_t udp_len;
  uint16_t udp_sum;
} __attribute__ ((packed)) ;
typedef struct sr_udp_hdr sr_udp_hdr_t;
/* =< udp set routines >===================================================== */
void sr_set_udp_src           (uint8_t * p, uint16_t dst_port);
void sr_set_udp_dst           (uint8_t * p, uint16_t dst_port);
void sr_set_udp_len           (uint8_t * p, uint16_t len);
void sr_set_udp_sum           (uint8_t * p, uint16_t len);
/* =< udp get routines >===================================================== */
uint16_t sr_get_udp_src       (uint8_t * p);
uint16_t sr_get_udp_dst       (uint8_t * p);
uint16_t sr_get_udp_len       (uint8_t * p);
uint16_t sr_get_udp_sum       (uint8_t * p);
/* ==< end udp header >====================================================== */

/* ==< ethernet header >===================================================== */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;
/* =< ethernet set routines >================================================ */
void sr_set_eth_dhost         (uint8_t * p, uint8_t * ether_dhost);
void sr_set_eth_shost         (uint8_t * p, uint8_t * ether_shost);
void sr_set_eth_type          (uint8_t * p, uint16_t ether_type);
/* =< ethernet get routines >================================================ */
uint8_t * sr_get_eth_dhost    (uint8_t * p);
uint8_t * sr_get_eth_shost    (uint8_t * p);
uint16_t sr_get_eth_type      (uint8_t * p);
/* ==< end ethernet header >================================================= */

/* ==< arp header >========================================================== */
struct sr_arp_hdr
{
    unsigned short  ar_hrd;                   /* format of hardware address   */
    unsigned short  ar_pro;                   /* format of protocol address   */
    unsigned char   ar_hln;                   /* length of hardware address   */
    unsigned char   ar_pln;                   /* length of protocol address   */
    unsigned short  ar_op;                    /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN];   /* sender hardware address      */
    uint32_t        ar_sip;                   /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN];   /* target hardware address      */
    uint32_t        ar_tip;                   /* target IP address            */
} __attribute__ ((packed)) ;
typedef struct sr_arp_hdr sr_arp_hdr_t;
/* =< arp set routines >==================================================== */
void sr_set_arp_hrd             (uint8_t * hdr, unsigned short hrd);
void sr_set_arp_pro             (uint8_t * hdr, unsigned short pro);
void sr_set_arp_hln             (uint8_t * hdr, unsigned short hln);
void sr_set_arp_pln             (uint8_t * hdr, unsigned short pln);
void sr_set_arp_op              (uint8_t * hdr, unsigned short op);
void sr_set_arp_sha             (uint8_t * hdr, unsigned char * sha);
void sr_set_arp_sip             (uint8_t * hdr, uint32_t sip);
void sr_set_arp_tha             (uint8_t * hdr, unsigned char * tha);
void sr_set_arp_tip             (uint8_t * hdr, uint32_t tip);
/* =< arp get routines >==================================================== */
unsigned short sr_get_arp_hrd   (uint8_t * hdr);
unsigned short sr_get_arp_pro   (uint8_t * hdr);
unsigned char sr_get_arp_hln    (uint8_t * hdr);
unsigned char sr_get_arp_pln    (uint8_t * hdr);
unsigned short sr_get_arp_op    (uint8_t * hdr);
unsigned char * sr_get_arp_sha  (uint8_t * hdr);
uint32_t sr_get_arp_sip         (uint8_t * hdr);
unsigned char * sr_get_arp_tha  (uint8_t * hdr);
uint32_t sr_get_arp_tip         (uint8_t * hdr);
/* ==< end arp header >====================================================== */

/* ==< union types >========================================================  */
union sr_tcp_pseudo_hdr {
  uint32_t u32[3];
  uint16_t u16[6];
  uint8_t u8[12];
};
typedef union sr_tcp_pseudo_hdr sr_tcp_pseudo_hdr_t;
/* ==< end union types >====================================================  */

/* ==< enums types >========================================================= */
enum sr_icmp3_code {
  icmp3_net  = 0x00,
  icmp3_host = 0x01,
  icmp3_port = 0x03,
};
enum sr_ip_protocol {
  ip_protocol_icmp = 0x0001,
  ip_protocol_tcp  = 0x0006,
  ip_protocol_udp  = 0x0011,
};
enum sr_ethertype {
  ethertype_arp = 0x0806,
  ethertype_ip  = 0x0800,
};
enum sr_arp_opcode {
  arp_op_request = 0x0001,
  arp_op_reply   = 0x0002,
};
enum sr_arp_hrd_fmt {
  arp_hrd_ethernet = 0x0001,
};
/* ==< end enums types >===================================================== */
#endif

