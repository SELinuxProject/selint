#ifndef MAPS_H
#define MAPS_H

#include <uthash.h>

#include "tree.h"
#include "selint_error.h"

struct hash_elem {
        char *name;
        char *module_name;
        UT_hash_handle hh_type, hh_role, hh_user, hh_class, hh_perm;
};

struct template_hash_elem {
	char *name;
	struct decl_list *declarations;
	struct if_call_list *calls;
	UT_hash_handle hh;
};

void insert_into_decl_map(char *type, char *module_name, enum decl_flavor flavor);

char *look_up_in_decl_map(char *type, enum decl_flavor flavor);

void insert_decl_into_template_map(char *name, enum decl_flavor flavor, char *declaration);

void insert_call_into_template_map(char *name, struct if_call_data *call);

struct template_hash_elem *look_up_in_template_map(char *name);

struct decl_list *look_up_decl_in_template_map(char *name);

struct if_call_list *look_up_call_in_template_map(char *name);

unsigned int decl_map_count(enum decl_flavor flavor);

void free_all_maps();

#endif
