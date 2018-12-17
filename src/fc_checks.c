#define _GNU_SOURCE
#include <stdio.h>

#include "fc_checks.h"
#include "maps.h"
#include "tree.h"

struct check_result * alloc_internal_error(char *string) {
	struct check_result *res = malloc(sizeof(struct check_result));
	res->severity = 'F';
	res->check_id = F_ID_INTERNAL;
	res->message = strdup(string);
	return res;
} 

struct check_result * check_file_context_types_exist(const struct check_data *check_data, struct policy_node *node) {

	if (node->flavor != NODE_FC_ENTRY) {
		return alloc_internal_error("File context type check called on non file context entry");
	} 

	struct fc_entry *entry = (struct fc_entry *)node->data;

	if (!entry) {
		return alloc_internal_error("Policy node data field is NULL");
	}

	char *type_decl_filename = look_up_in_type_map(entry->context->type);

	if (!type_decl_filename) {
		struct check_result *res = malloc(sizeof(struct check_result));
		res->severity = 'E';
		res->check_id = E_ID_FC_TYPE;
		if (!asprintf(&res->message, "Nonexistent type (%s) listed in fc_entry", entry->context->type)) {
			free(res);
			return alloc_internal_error("Failed to generate error message in fc type checking"); 
		}

		return res;
	}

	return NULL;
}

struct check_result *check_file_context_types_in_mod(struct policy_node *node) {
	return NULL;
}

struct check_result *check_file_context_roles(struct policy_node *node) {
	return NULL;
}

struct check_result *check_file_context_users(struct policy_node *node) {
	return NULL;
}

struct check_result *check_file_context_error_nodes(struct policy_node *node) {
	return NULL;
}
