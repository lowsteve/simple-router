#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* ---< private functions >-------------------------------------------------- */
/* --< is unsolicited syn >-------------------------------------------------- */
/* --< is ip predicate >----------------------------------------------------- */
static bool
sr_nat_is_ip_packet(uint8_t * packet,
  unsigned int len)
{
  if(sr_validate_ethernet(packet,len))
    return false;

  uint16_t etht = ethertype(packet);
  if(etht != ethertype_ip)
    return false;

  if(sr_validate_ip(packet,len))
    return false;
return true;
}
static uint32_t
sr_get_nat_ip_internal(struct sr_instance * sr)
{
  struct sr_if * iface = sr_get_interface(sr,NAT_INTERNAL_IF);
  return iface->ip;
}
/* --< aux helpers >--------------------------------------------------------- */
/* -< icmp aux allocator >--------------------------------------------------- */
static uint16_t
sr_nat_assign_icmp_aux_int (uint8_t * packet)
{
  return sr_get_icmp8_id(packet);
}
/* -< get aux_int >---------------------------------------------------------- */
static uint16_t
sr_nat_get_aux_int (uint8_t * packet,
  unsigned int len,
  sr_nat_mapping_type ip_p)
{
  uint16_t aux_int = 0;

  if(ip_p == nat_mapping_icmp) {
    if(sr_validate_icmp(packet,len)) {
      return aux_int;
    }
    if(sr_get_icmp_type(packet) == ICMP_ECHO_REQUEST) {
      return sr_nat_assign_icmp_aux_int(packet);
    }
  }


  if(ip_p == nat_mapping_tcp) {
    if(sr_validate_tcp(packet,len)){
      return aux_int;
    }
    return sr_get_tcp_src(packet);
  }

  if(ip_p == nat_mapping_udp) {
    if(sr_validate_udp(packet,len)){
      return aux_int;
    }
    return sr_get_udp_src(packet);
  }

  return aux_int;
}
/* -< get aux_ext >---------------------------------------------------------- */
static uint16_t
sr_nat_get_aux_ext (uint8_t * packet,
  unsigned int len,
  sr_nat_mapping_type ip_p)
{
  uint16_t aux_ext = 0;

  if(ip_p == nat_mapping_icmp) {
    if(sr_validate_icmp(packet,len)) {
      return aux_ext;
    }
    if(sr_get_icmp_type(packet) == ICMP_ECHO_REPLY) {
      return sr_get_icmp0_id(packet);
    }
  }

  if(ip_p == nat_mapping_tcp) {
    if(sr_validate_tcp(packet,len)){
      return aux_ext;
    }
    return sr_get_tcp_dst(packet);
  }

  if(ip_p == nat_mapping_udp) {
    if(sr_validate_udp(packet,len)){
      return aux_ext;
    }
    return sr_get_udp_dst(packet);
  }

  return aux_ext;
}
/* --< get mapping type >---------------------------------------------------- */
static sr_nat_mapping_type
sr_nat_get_mapping_type (uint8_t * packet)
{
  uint8_t ip_p = sr_get_ip_p(packet);
  if(ip_p == ip_protocol_icmp)  return nat_mapping_icmp;
  if(ip_p == ip_protocol_tcp)   return nat_mapping_tcp;
  if(ip_p == ip_protocol_udp)   return nat_mapping_udp;
  return nat_mapping_unknown;
}
/* ---< cache helpers >------------------------------------------------------ */
/* --< get cache entry type >------------------------------------------------ */
static sr_nat_cache_entry_type
sr_nat_get_cache_entry_type (struct sr_nat_mapping * cache_entry)
{
  if (cache_entry == NULL) {
    return cache_entry_miss;
  }
  if (!(cache_entry->ip_int && cache_entry->aux_int)) {
    return cache_entry_partial_hit;
  }
  return cache_entry_complete_hit;
}
/* --< handle cache miss >--------------------------------------------------- */
static void
sr_nat_handle_cache_miss(struct sr_instance * sr,
  uint8_t * packet,
  uint16_t aux_ext,
  unsigned int len,
  sr_nat_mapping_type mapping_type)
{
    if (mapping_type == nat_mapping_tcp) {
      if (sr_get_tcp_syn(packet)) {
        sr_nat_insert_syn(sr,aux_ext);
        sr_nat_append_connection(sr->nat, packet, aux_ext, len);
      }
    }
    return;
}
/* --< handle cache partial hit >-------------------------------------------- */
static void
sr_nat_handle_cache_partial_hit(struct sr_instance * sr,
  uint8_t * packet,
  uint16_t aux_ext,
  unsigned int len,
  sr_nat_mapping_type mapping_type)
{
    if (mapping_type == nat_mapping_tcp) {
      if (sr_get_tcp_syn(packet)) {
        sr_nat_append_connection(sr->nat,packet,aux_ext,len);
      }
    }
    return;
}
/* ---< rewrite routines >--------------------------------------------------- */
/* --< internal rewrite >---------------------------------------------------- */
static void
sr_nat_rewrite_internal (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len,
  struct sr_nat_mapping * natcache_entry)
{
  sr_set_ip_src(packet,natcache_entry->ip_ext);
  /* TODO : tcp + udp */
  sr_compute_set_ip_sum(packet);
  return;
}
/* --< external rewrite >---------------------------------------------------- */
static void
sr_nat_rewrite_external (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len,
  struct sr_nat_mapping * natcache_entry)
{
  sr_set_ip_dst(packet,natcache_entry->ip_int);
  /* TODO tcp + udp */
  sr_compute_set_ip_sum(packet);
  return;
}
/* ---< translation routines >----------------------------------------------- */
/* --< internal translation >------------------------------------------------ */
static void
sr_nat_translate_internal (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len)
{
  if(sr_get_ip_dst(packet) == sr_get_nat_ip_internal(sr)) return;

  sr_nat_mapping_type mapping_type = sr_nat_get_mapping_type(packet);
  if(mapping_type == nat_mapping_unknown) return;
  uint16_t aux_int = sr_nat_get_aux_int(packet,len,mapping_type);

  struct sr_nat_mapping * natcache_entry;
  natcache_entry = sr_nat_lookup_internal(sr->nat,sr_get_ip_src(packet),
      aux_int, mapping_type);
  sr_nat_cache_entry_type entry_type;
  entry_type = sr_nat_get_cache_entry_type(natcache_entry);

  if(entry_type == cache_entry_miss) {
    natcache_entry = sr_nat_insert_mapping(sr,sr_get_ip_src(packet),
        aux_int,mapping_type);
  }
  if(entry_type == cache_entry_partial_hit) {
    sr_nat_remove_entry(sr->nat, natcache_entry);
  }

  assert(natcache_entry);
  sr_nat_rewrite_internal(sr,packet,len,natcache_entry);
  free(natcache_entry);
}
/* --< external translation >------------------------------------------------ */
static void
sr_nat_translate_external (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len)
{
  sr_nat_mapping_type mapping_type = sr_nat_get_mapping_type(packet);
  if(mapping_type == nat_mapping_unknown) return;
  uint16_t aux_ext = sr_nat_get_aux_ext(packet,len,mapping_type);

  /* FIXME -- */
  if((mapping_type == nat_mapping_tcp) && (ntohs(aux_ext) < 1025)) {
    return;
  }
  /* -- FIXME */

  struct sr_nat_mapping * natcache_entry;
  natcache_entry = sr_nat_lookup_external(sr->nat,aux_ext,mapping_type);
  sr_nat_cache_entry_type entry_type;
  entry_type = sr_nat_get_cache_entry_type(natcache_entry);

  if(entry_type == cache_entry_miss) {
    sr_nat_handle_cache_miss(sr,packet,aux_ext,len,mapping_type);
    return;
  }
  if (entry_type == cache_entry_partial_hit) {
    sr_nat_handle_cache_partial_hit(sr,packet,aux_ext,len,mapping_type);
    return;
  }

  assert(natcache_entry);
  sr_nat_rewrite_external(sr,packet,len,natcache_entry);
  free(natcache_entry);
  return  ;
}
/* ---< public nat interface >----------------------------------------------- */
void
sr_nat (struct sr_instance * sr,
  uint8_t * packet,
  unsigned int len,
  char * interface)
{
  assert(sr);
  assert(sr->nat);
  assert(packet);

  if(sr_nat_is_ip_packet(packet,len) == false) return;

  if(strcmp(interface,NAT_INTERNAL_IF) == 0) {
    sr_nat_translate_internal(sr,packet,len);
    return;
  }

  if(strcmp(interface,NAT_EXTERNAL_IF) == 0) {
    sr_nat_translate_external(sr,packet,len);
    return;
  }

  return;
}
/* --< constructor >--------------------------------------------------------- */
int
sr_nat_init (struct sr_instance * sr, struct sr_nat * nat) 
{
  assert(nat);

  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_natcache_timeout, sr);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}
/* --< destructor >---------------------------------------------------------- */
int
sr_nat_destroy (struct sr_nat * nat) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping * map_it = nat->mappings;
  struct sr_nat_mapping * temp = NULL;

  while(map_it != NULL) {
    temp = map_it->next;
    free(map_it);
    map_it = temp;
  }

  pthread_mutex_unlock(&(nat->lock));

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}
