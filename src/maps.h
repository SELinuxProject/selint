#ifndef MAPS_H
#define MAPS_H

#include <uthash.h>

#include "selint_error.h"

struct hash_elem {
        char *name;
        char *module_name;
        UT_hash_handle hh_type; //TODO: Other hash tables for other things that are declared
};

void insert_into_type_map(char *type, char *module_name);

char *look_up_in_type_map(char *type);

unsigned int type_map_count();

void free_all_maps();

#endif
