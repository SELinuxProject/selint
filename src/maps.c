#include "maps.h"

struct hash_elem *type_map = NULL;
struct template_hash_elem *template_map = NULL;

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

void insert_into_template_map(char *name, enum decl_flavor flavor, char *declaration) {

	struct template_hash_elem *template;

	struct declaration_data *new_data = malloc(sizeof(struct declaration_data));
	new_data->flavor = flavor;
	new_data->name = strdup(declaration);
	new_data->attrs = NULL; //Not needed

	struct decl_list *new_node = malloc(sizeof(struct decl_list));
	new_node->decl = new_data;
	new_node->next = NULL;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	if ( template == NULL) {
		template = malloc(sizeof(struct template_hash_elem));
		template->name = strdup(name);
		template->declarations = new_node;

		HASH_ADD_KEYPTR(hh, template_map, template->name, strlen(template->name), template);

	} else {
		// We've already stored some declarations from this template
		struct decl_list *cur = template->declarations;
		while (cur->next) { cur = cur->next; }
		cur->next = new_node;
	}
}

struct decl_list *look_up_in_template_map(char *name) {

	struct template_hash_elem *template;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	if (template == NULL) {
		return NULL;
	} else {
		return template->declarations;
	}
}

void free_all_maps() {

	struct hash_elem *cur_type, *tmp_type;

	HASH_ITER(hh_type, type_map, cur_type, tmp_type) {
		HASH_DELETE(hh_type, type_map, cur_type);
		free(cur_type->name);
		free(cur_type->module_name);
		free(cur_type);
	}

	struct template_hash_elem *cur_template, *tmp_template;

	HASH_ITER(hh, template_map, cur_template, tmp_template) {
		HASH_DELETE(hh, template_map, cur_template);
		free(cur_template->name);
		free_decl_list(cur_template->declarations);
		free(cur_template);
	}
}
