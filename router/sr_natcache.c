#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_nat.h"
#include "sr_router.h"
#include "sr_utils_nat.h"



static void
sr_nat_drop_syns(struct sr_nat_mapping * natcache_entry)
{
  struct sr_nat_connection * conns = natcache_entry->conns;
  struct sr_nat_connection * temp = NULL;
  if (conns == NULL) { return; }

  while(conns != NULL) {
    temp = conns->next;
    free(conns);
    conns = temp;
  }
  return;
}

void
sr_nat_remove_entry(
  struct sr_nat * nat,
  struct sr_nat_mapping * natcache_entry)
{
  struct sr_nat_mapping ** prev = &(nat->mappings);
  struct sr_nat_mapping * curr = nat->mappings;

  /* eieio - ugly hacks */
  pthread_mutex_lock(&(nat->lock));

  while(curr) {
    if(curr == natcache_entry) {
      *prev = curr->next;
      free(curr);
      break;
    }
    *prev = curr;
    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return;
}

void
sr_nat_send_icmp3 (
  struct sr_instance * sr,
  struct sr_nat_connection * conns)
{
  struct sr_nat_connection * temp = NULL;

  if (conns == NULL) { return; }

  while(conns != NULL) {
    sr_send_icmp3(sr,conns->packet,conns->len,conns->interface,icmp3_port);
    temp = conns->next;
    free(conns);
    conns = temp;
  }
}

void *
sr_natcache_timeout(void * sr_ptr) {
  struct sr_instance * sr = (struct sr_instance *)sr_ptr;
  struct sr_nat * nat = ((struct sr_instance *)sr_ptr)->nat;
  struct sr_nat_mapping * map_it = NULL;
  struct sr_nat_mapping * temp = NULL;

  while (1) {
    sleep(5.0); /* eieio - dirty hack */

    pthread_mutex_lock(&(nat->lock));
    time_t curtime = time(NULL);
    map_it = nat->mappings;

    while(map_it != NULL) {
      if(difftime(curtime,map_it->last_updated) > SR_NAT_TO) {
        sr_nat_send_icmp3(sr,map_it->conns);
        temp = map_it->next;
        sr_nat_remove_entry(nat,map_it);
      }
      map_it = temp;
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

struct sr_nat_mapping *
sr_nat_lookup_external (
  struct sr_nat * nat,
  uint16_t aux_ext,
  sr_nat_mapping_type type)
{
  struct sr_nat_mapping * needle;
  struct sr_nat_mapping * copy = NULL;

  pthread_mutex_lock(&(nat->lock));
  needle = sr_nat_search_ext_nat_mappings(nat->mappings,aux_ext,type);
  if(needle) {
    copy = sr_nat_allocate_nat_mapping();
    sr_nat_memcpy_nat_mapping(copy,needle);
  }
  pthread_mutex_unlock(&(nat->lock));


  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *
sr_nat_lookup_internal (
  struct sr_nat *nat,
   uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type)
{
  struct sr_nat_mapping * copy = NULL;
  struct sr_nat_mapping * needle;

  pthread_mutex_lock(&(nat->lock));
  needle = sr_nat_search_int_nat_mappings(nat->mappings,ip_int,aux_int,type);
  if(needle) {
    copy = sr_nat_allocate_nat_mapping();
    sr_nat_memcpy_nat_mapping(copy,needle);
  }
  pthread_mutex_unlock(&(nat->lock));

  return copy;
}

void
sr_nat_append_connection (
  struct sr_nat * nat,
  uint8_t * packet,
  uint16_t aux_ext,
  unsigned long len)
{
  struct sr_nat_mapping * needle;
  struct sr_nat_connection * conn = sr_nat_allocate_nat_connection();

  /* we only use this for external mapping */
  sr_nat_construct_nat_connection(conn, packet, len, NAT_EXTERNAL_IF);

  pthread_mutex_lock(&(nat->lock));
  needle = sr_nat_search_ext_nat_mappings(nat->mappings,aux_ext,nat_mapping_tcp);
  if(needle) {
    needle->conns = sr_nat_append_mapping_connection(needle->conns, conn);
  }
  pthread_mutex_unlock(&(nat->lock));

  return;
}

void
sr_nat_insert_syn (
  struct sr_instance * sr,
  uint16_t aux_ext)
{
  struct sr_nat * nat = sr->nat;
  struct sr_nat_mapping * mapping = sr_nat_allocate_nat_mapping();

  sr_nat_construct_nat_mapping_external(sr,mapping,aux_ext,nat_mapping_tcp);

  pthread_mutex_lock(&(nat->lock));
  nat->mappings = sr_nat_append_nat_mappings(nat->mappings, mapping);
  pthread_mutex_unlock(&(nat->lock));

  return;
}

struct sr_nat_mapping *
sr_nat_insert_mapping (
  struct sr_instance * sr,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type)
{
  struct sr_nat * nat = sr->nat;
  struct sr_nat_mapping * copy = sr_nat_allocate_nat_mapping();
  struct sr_nat_mapping * mapping = sr_nat_allocate_nat_mapping();

  sr_nat_construct_nat_mapping(sr,mapping,ip_int,aux_int,type);
  sr_nat_memcpy_nat_mapping(copy,mapping);

  pthread_mutex_lock(&(nat->lock));
  nat->mappings = sr_nat_append_nat_mappings(nat->mappings,mapping);
  pthread_mutex_unlock(&(nat->lock));

  return copy;
}
