#include "maps.h"

struct hash_elem *type_map = NULL;
struct hash_elem *role_map = NULL;
struct hash_elem *user_map = NULL;
struct template_hash_elem *template_map = NULL;

struct hash_elem *look_up_hash_elem(char *name, enum decl_flavor flavor) {

	struct hash_elem *decl;

	switch (flavor) {
		case DECL_TYPE:
			HASH_FIND(hh_type, type_map, name, strlen(name), decl);
			break;
		case DECL_ROLE:
			HASH_FIND(hh_role, role_map, name, strlen(name), decl);
			break;
		case DECL_USER:
			HASH_FIND(hh_user, user_map, name, strlen(name), decl);
			break;
		default:
			decl = NULL;
	}

	return decl;
}

void insert_into_decl_map(char *name, char *module_name, enum decl_flavor flavor) {

	struct hash_elem *decl = look_up_hash_elem(name, flavor);

	if (decl == NULL) { // Item not in hash table already

		decl = malloc(sizeof(struct hash_elem));
		decl->name = strdup(name);
		decl->module_name = strdup(module_name);

		switch (flavor) {
			case DECL_TYPE:
				HASH_ADD_KEYPTR(hh_type, type_map, decl->name, strlen(decl->name), decl);
				break;
			case DECL_ROLE:
				HASH_ADD_KEYPTR(hh_role, role_map, decl->name, strlen(decl->name), decl);
				break;
			case DECL_USER:
				HASH_ADD_KEYPTR(hh_user, user_map, decl->name, strlen(decl->name), decl);
				break;
			default:
				return;
		}
	} //TODO: else report error?
}

char *look_up_in_decl_map(char *name, enum decl_flavor flavor) {
	
	struct hash_elem *decl = look_up_hash_elem(name, flavor);

	if (decl == NULL) {
		return NULL;
	} else {
		return decl->module_name;
	}
}

unsigned int decl_map_count(enum decl_flavor flavor) {
	switch (flavor) {
		case DECL_TYPE:
			return HASH_CNT(hh_type, type_map);
		case DECL_ATTRIBUTE:
			return 0;
		case DECL_ROLE:
			return HASH_CNT(hh_role, role_map);
		case DECL_USER:
			return HASH_CNT(hh_user, user_map);
		default:
			return 0;
	}
}

void insert_decl(struct template_hash_elem *template, void *new_node) {
	if (template->declarations) {
		struct decl_list *cur = template->declarations;
		while (cur->next) { cur = cur->next; }
		cur->next = (struct decl_list *) new_node;
	} else {
		template->declarations = (struct decl_list *) new_node;
	}
}

void insert_call(struct template_hash_elem *template, void *new_node) {
	if (template->calls) {
		struct if_call_list *cur = template->calls;
		while (cur->next) { cur = cur->next; }
		cur->next = (struct if_call_list *) new_node;
	} else {
		template->calls = (struct if_call_list *) new_node;
	}
}

void insert_into_template_map(char *name, void *new_node, void (*insertion_func)(struct template_hash_elem *, void *)) {
	
	struct template_hash_elem *template;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	if ( template == NULL) {
		template = malloc(sizeof(struct template_hash_elem));
		template->name = strdup(name);
		template->declarations = NULL;
		template->calls = NULL;

		HASH_ADD_KEYPTR(hh, template_map, template->name, strlen(template->name), template);

	}

	insertion_func(template, new_node);
}


void insert_decl_into_template_map(char *name, enum decl_flavor flavor, char *declaration) {

	struct declaration_data *new_data = malloc(sizeof(struct declaration_data));
	new_data->flavor = flavor;
	new_data->name = strdup(declaration);
	new_data->attrs = NULL; //Not needed

	struct decl_list *new_node = malloc(sizeof(struct decl_list));
	new_node->decl = new_data;
	new_node->next = NULL;

	insert_into_template_map(name, new_node, insert_decl);
}

void insert_call_into_template_map(char *name, struct if_call_data *call) {

	struct if_call_list *new_node = malloc(sizeof(struct if_call_list));
	new_node->call = call;
	new_node->next = NULL;

	insert_into_template_map(name, new_node, insert_call);
}

struct template_hash_elem *look_up_in_template_map(char *name) {

	struct template_hash_elem *template;

	HASH_FIND(hh, template_map, name, strlen(name), template);

	return template;
}

struct decl_list *look_up_decl_in_template_map(char *name) {
	struct template_hash_elem *template = look_up_in_template_map(name);

	if (template) {
		return template->declarations;
	} else {
		return NULL;
	}
}

struct if_call_list *look_up_call_in_template_map(char *name) {
	struct template_hash_elem *template = look_up_in_template_map(name);

	if (template) {
		return template->calls;
	} else {
		return NULL;
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
		free_if_call_list(cur_template->calls);
		free(cur_template);
	}
}
