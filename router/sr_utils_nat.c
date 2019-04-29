#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sr_router.h"
#include "sr_nat.h"
#include "sr_protocol.h"

void
sr_print_conns(struct sr_nat_connection * conns_list)
{
  if(conns_list == NULL) {
    fprintf(stderr, "\tConns list: NULL\n");
    return;
  }
  fprintf(stderr, "\tConns:\n");
  while(conns_list) {
    fprintf(stderr,"\t\tPacket: %p\n",conns_list->packet);
    fprintf(stderr,"\t\tLen: %d\n",conns_list->len);
    fprintf(stderr,"\t\tInterface: %s\n",conns_list->interface);
    fprintf(stderr,"\n");
    conns_list = conns_list->next;
  }
  return;
}

void
sr_print_natcache(struct sr_instance * sr)
{
  struct sr_nat * nat = sr->nat;
  struct sr_nat_mapping * mappings = nat->mappings;
  if(mappings == NULL) {
    fprintf(stderr, "\tFailed to print nat mappings. nat-> mappings is NULL\n");
    return;
  }
  fprintf(stderr, "Head of mappings list:\n");
  while(mappings) {
    fprintf(stderr, "\tip_int: %d\n", mappings->ip_int);
    fprintf(stderr, "\tip_ext: %d\n", mappings->ip_ext);
    fprintf(stderr, "\taux_int: %d\n", mappings->aux_int);
    fprintf(stderr, "\taux_ext: %d\n", mappings->ip_int);
    fprintf(stderr, "\tlast update: %lld\n", (long long)mappings->last_updated);
    sr_print_conns(mappings->conns);
    fprintf(stderr, "\n");
    mappings = mappings->next;
  }
  return;
}

/* ---< private routines >--------------------------------------------------- */
/* --< allocators >---------------------------------------------------------- */
/* -< external port >-------------------------------------------------------- */
static uint16_t
sr_nat_assign_ext_aux (void)
{
  static uint16_t next_ext_aux = 1023;
  next_ext_aux++;
  if(next_ext_aux == 0) next_ext_aux = 1024;
  return next_ext_aux;
}
/* --< nap ip's>------------------------------------------------------------- */
/* -< get nat internal ip >-------------------------------------------------- */
uint32_t
sr_get_nat_ip_internal(struct sr_instance * sr)
{
  struct sr_if * iface = sr_get_interface(sr,NAT_INTERNAL_IF);
  return iface->ip;
}
/* -< get nat external ip>--------------------------------------------------- */
uint32_t
sr_get_nat_ip_external(struct sr_instance * sr)
{
  struct sr_if * iface = sr_get_interface(sr,NAT_EXTERNAL_IF);
  return iface->ip;
}
/* ---< public routines >---------------------------------------------------- */
/* --< allocators >---------------------------------------------------------- */
/* -< struct sr_nat_mapping >------------------------------------------------ */
struct sr_nat_mapping *
sr_nat_allocate_nat_mapping_internal (
  const char * file,
  const char * function,
  int line )
{
  struct sr_nat_mapping * mapping = malloc(sizeof(struct sr_nat_mapping));
  if(mapping == NULL) {
    fprintf(stderr,"[ERR] sr_nat_mapping allocation failed : %s - %s %s %d\n",
      strerror(errno),file,function,line);
    exit(EXIT_FAILURE);
  }
  return mapping;
}

struct sr_nat_connection *
sr_nat_allocate_nat_connection_external (
  const char * file,
  const char * function,
  int line)
{
  struct sr_nat_connection * conn = malloc(sizeof(struct sr_nat_connection));
  if (conn == NULL) {
    fprintf(stderr,"[ERR] sr_nat_connection allocation failed : %s - %s %s %d\n",
      strerror(errno),file,function,line);
    exit(EXIT_FAILURE);
  }
  return conn;
}

/* --< constructors >-------------------------------------------------------- */
/* --< struct sr_nat_mapping >----------------------------------------------- */
void
sr_nat_construct_nat_mapping (
  struct sr_instance * sr,
  struct sr_nat_mapping * mapping,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type )
{
  if(mapping == NULL) return;

  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = sr_get_nat_ip_external(sr);
  mapping->aux_int = aux_int;
  mapping->aux_ext = sr_nat_assign_ext_aux();
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = NULL;
}

void
sr_nat_construct_nat_mapping_external (
  struct sr_instance * sr,
  struct sr_nat_mapping * mapping,
  uint16_t aux_ext,
  sr_nat_mapping_type type )
{
  if (mapping == NULL) return;
  mapping->type = type;
  mapping->ip_int = 0;
  mapping->ip_ext = sr_get_nat_ip_external(sr);
  mapping->aux_int = 0;
  mapping->aux_ext = aux_ext;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = NULL;
  return;
}

void sr_nat_construct_nat_connection(
  struct sr_nat_connection * conn,
  uint8_t * packet,
  unsigned long len,
  char * interface)
{
  if (conn == NULL) return;
  conn->packet = packet;
  conn->len = len;
  conn->interface = interface;
  conn->next = NULL;
}

/* --< connection operations >----------------------------------------------- */

struct sr_nat_connection * sr_nat_append_mapping_connection(
  struct sr_nat_connection * list,
  struct sr_nat_connection * tail)
{
  if(list == NULL) return tail;
  if(tail == NULL) return list;

  while(list->next) {list = list->next; }

  list->next = tail;
  return list;
}
/* --< mappings operations >------------------------------------------------- */
/* -< append >--------------------------------------------------------------- */
struct sr_nat_mapping *
sr_nat_append_nat_mappings (
  struct sr_nat_mapping * list,
  struct sr_nat_mapping * tail )
{
  if(list == NULL && tail == NULL) return NULL;
  if(list == NULL) return tail;
  if(tail == NULL) return list;

  while(list->next) { list = list->next; }

  list->next = tail;
  return list;
}
/* -< internal lookup >------------------------------------------------------ */
struct sr_nat_mapping *
sr_nat_search_int_nat_mappings (
  struct sr_nat_mapping * map_it,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type )

{
  while(map_it) {
    if(   type    == map_it->type
       && ip_int  == map_it->ip_ext
       && aux_int == map_it->aux_ext)
    {
      break;
    }
    map_it = map_it->next;
  }
  return map_it;
}
/* -< external lookup >------------------------------------------------------ */
struct sr_nat_mapping *
sr_nat_search_ext_nat_mappings (
  struct sr_nat_mapping * map_it,
  uint32_t aux_ext,
  sr_nat_mapping_type type )
{
  while(map_it) {
    if(   type    == map_it->type
       && aux_ext == map_it->aux_int)
    {
      break;
    }
    if(   type    == map_it->type
       && map_it->aux_int == 0
       && aux_ext == map_it->aux_ext)
    {
      break;
    }
    map_it = map_it->next;
  }
  return map_it;
}
