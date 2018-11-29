#ifndef MAPS_H
#define MAPS_H

#include <uthash.h>

#include "tree.h"
#include "selint_error.h"

struct hash_elem {
        char *name;
        char *module_name;
        UT_hash_handle hh_type; //TODO: Other hash tables for other things that are declared
};

struct template_hash_elem {
	char *name;
	struct decl_list *declarations;
	UT_hash_handle hh;
};

void insert_into_type_map(char *type, char *module_name);

char *look_up_in_type_map(char *type);

void insert_into_template_map(char *name, enum decl_flavor flavor, char *declaration);

struct decl_list *look_up_in_template_map(char *name);

unsigned int type_map_count();

void free_all_maps();

#endif
