#ifndef SR_NAT_H
#define SR_NAT_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include "sr_rt.h"

#define SR_NAT_TO 5

#define NAT_EXTERNAL_IF "eth2"
#define NAT_INTERNAL_IF "eth1"

#ifdef SR_DEBUG_NAT
#define NAT_PRINTD(fmt,...) fprintf(stderr,"DEBUG NAT - %s:%d:%s() " fmt, \
  __FILE__,__LINE__,__func__, ##__VA_ARGS__)
#else
#define NAT_PRINTD(fmt,...)
#endif


typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_udp,
  nat_mapping_unknown
} sr_nat_mapping_type;

typedef enum {
  ip_internal_origin,
  ip_external_origin,
  ip_unknown_origin
} sr_ip_origin_type;

typedef enum {
  cache_entry_miss,
  cache_entry_partial_hit,
  cache_entry_complete_hit
} sr_nat_cache_entry_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint8_t * packet;
  unsigned int len;
  char * interface;
  struct sr_nat_connection * next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int;  /* internal ip addr */
  uint32_t ip_ext;  /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection * conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping * next;
};


struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping * mappings;
  uint32_t ip_int;
  uint32_t ip_ext;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread; /* time out thread */
};

int   sr_nat_init(struct sr_instance * sr, struct sr_nat * nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_natcache_timeout(void *nat_ptr);  /* Periodic Timout */
void sr_nat_send_icmp3(struct sr_instance * sr, struct sr_nat_connection * conns);
void sr_nat (struct sr_instance * sr, uint8_t * packet, unsigned int len,char * interace);

/* remove natcache_entry from the nat */
void
sr_nat_remove_entry(
  struct sr_nat * nat,
  struct sr_nat_mapping * natcache_entry);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping * sr_nat_lookup_external(
  struct sr_nat *nat,
  uint16_t aux_ext,
  sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping * sr_nat_lookup_internal(
  struct sr_nat *nat,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type);

/* Append a connection to the mapping given by aux_ext. */
void
sr_nat_append_connection(
  struct sr_nat * nat,
  uint8_t * packet,
  uint16_t aux_ext,
  unsigned long len);

/* Insert a new external mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
void
sr_nat_insert_syn(
  struct sr_instance * sr,
  uint16_t aux_ext);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping * sr_nat_insert_mapping(
  struct sr_instance * sr,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type);
#endif

