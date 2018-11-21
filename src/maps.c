#include "maps.h"

struct hash_elem *type_map = NULL;

void insert_into_type_map(char *name, char *module_name) {

	struct hash_elem *type;

	HASH_FIND(hh_type, type_map, name, strlen(name), type);

	if (type == NULL) { // Type not in hash table already

		type = malloc(sizeof(struct hash_elem));
		type->name = strdup(name);
		type->module_name = strdup(module_name);

		HASH_ADD_KEYPTR(hh_type, type_map, type->name, strlen(type->name), type);
	} //TODO: else report error?
}

char *look_up_in_type_map(char *name) {
	
	struct hash_elem *type;

	HASH_FIND(hh_type, type_map, name, strlen(name), type);

	if (type == NULL) {
		return NULL;
	} else {
		return type->module_name;
	}
}

unsigned int type_map_count() {
	return HASH_CNT(hh_type, type_map);
}

void free_all_maps() {

	struct hash_elem *cur_type, *tmp;

	HASH_ITER(hh_type, type_map, cur_type, tmp) {
		HASH_DELETE(hh_type, type_map, cur_type);
		free(cur_type->name);
		free(cur_type->module_name);
	}
}
