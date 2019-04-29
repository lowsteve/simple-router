#ifndef SR_UTILS_NAT_H
#define SR_UTILS_NAT_H

#include "sr_nat.h"

#define sr_nat_allocate_nat_mapping() \
  sr_nat_allocate_nat_mapping_internal( __FILE__,__FUNCTION__,__LINE__)

#define sr_nat_allocate_nat_connection() \
  sr_nat_allocate_nat_connection_external(__FILE__,__FUNCTION__,__LINE__)

#define sr_nat_memcpy_nat_mapping(dst,src) \
  memcpy(dst,src,sizeof(struct sr_nat_mapping))

void
sr_print_natcache(struct sr_instance * sr);

/* --< allocators >---------------------------------------------------------- */

struct sr_nat_mapping * sr_nat_allocate_nat_mapping_internal(
  const char * file,
  const char * function,
  int line);

struct sr_nat_connection * sr_nat_allocate_nat_connection_external(
  const char * file,
  const char * function,
  int line);

/* --< constructors >-------------------------------------------------------- */

void sr_nat_construct_nat_mapping(
  struct sr_instance * sr,
  struct sr_nat_mapping * mapping,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type);

void sr_nat_construct_nat_mapping_external(
  struct sr_instance * sr,
  struct sr_nat_mapping * mapping,
  uint16_t aux_ext,
  sr_nat_mapping_type type );

void sr_nat_construct_nat_connection(
  struct sr_nat_connection * conn,
  uint8_t * packet,
  unsigned long len,
  char * interface);

/* --< connection operations >----------------------------------------------- */

struct sr_nat_connection * sr_nat_append_mapping_connection(
  struct sr_nat_connection * list,
  struct sr_nat_connection * tail);

/* --< mappings operations >------------------------------------------------- */

struct sr_nat_mapping * sr_nat_append_nat_mappings(
  struct sr_nat_mapping * list,
  struct sr_nat_mapping * tail);

struct sr_nat_mapping * sr_nat_search_int_nat_mappings(
  struct sr_nat_mapping * map_it,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type);

struct sr_nat_mapping * sr_nat_search_ext_nat_mappings(
  struct sr_nat_mapping * map_it,
  uint32_t aux_ext,
  sr_nat_mapping_type type);
#endif

