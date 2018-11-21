#include <stdlib.h>
#include <string.h>

#include "parse_functions.h"
#include "selint_error.h"
#include "tree.h"

char *module_name = NULL;

enum selint_error begin_parsing_te(struct policy_node **cur, char *mn) {

	set_current_module_name(mn);

	*cur = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}

	memset(*cur, 0, sizeof(struct policy_node));

	(*cur)->flavor = NODE_TE_FILE;
	(*cur)->data = strdup(mn);

	return SELINT_SUCCESS;
}

void set_current_module_name(char *mn) {
	if (module_name != NULL) {
		free(module_name);
	}
	module_name = strdup(mn);
}

char * get_current_module_name() {
	return module_name;
}

enum selint_error insert_declaration(struct policy_node **cur, char *flavor, char *name) {
	//TODO: Handle attributes
	//TODO: Insert type in hash table (Actually, it should be on the first pass
	// after building the tree, right?)

	char *mn = get_current_module_name();

	if (!mn) {
		return SELINT_NO_MOD_NAME;
	}

	insert_into_type_map(name, mn);

	struct declaration_data *data = (struct declaration_data *) malloc(sizeof(struct declaration_data));
	if (!data) {
		return SELINT_OUT_OF_MEM;
	}

	memset(data, 0, sizeof(struct declaration_data));

	enum decl_flavor flavor_to_set = DECL_TYPE; // TODO: Other flavors
	data->flavor = flavor_to_set;
	data->name = strdup(name);

	enum selint_error ret = insert_policy_node_next(*cur, NODE_DECL, data);

	if (ret != SELINT_SUCCESS) {
		free(data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_av_rule(struct policy_node **cur, char *flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms) {
	return SELINT_SUCCESS;
}


enum selint_error begin_optional_policy(struct policy_node **cur) {

	enum selint_error ret = insert_policy_node_next(*cur, NODE_OPTIONAL_POLICY, NULL);

	if (ret != SELINT_SUCCESS) {
		return ret;
	}

	*cur = (*cur)->next;

	ret = insert_policy_node_child(*cur, NODE_START_BLOCK, NULL);
	if (ret != SELINT_SUCCESS) {
		*cur = (*cur)->prev;
		free_policy_node(*cur);
		return ret;
	}

	*cur = (*cur)->first_child;

	return SELINT_SUCCESS;
}

void cleanup_parsing() {
	if (module_name) {
		free(module_name);
		module_name = NULL;
	}

	free_all_maps();
}
