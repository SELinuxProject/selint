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

struct check_result * check_file_context_types_exist(const struct check_data *check_data, const struct policy_node *node) {

	if (node->flavor != NODE_FC_ENTRY) {
		return alloc_internal_error("File context type check called on non file context entry");
	} 

	struct fc_entry *entry = (struct fc_entry *)node->data;

	if (!entry) {
		return alloc_internal_error("Policy node data field is NULL");
	}

	char *type_decl_filename = look_up_in_decl_map(entry->context->type, DECL_TYPE);

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

struct check_result *check_file_context_types_in_mod(const struct check_data *check_data, const struct policy_node *node) {

	if (node->flavor != NODE_FC_ENTRY) {
		return alloc_internal_error("File context type check called on non file context entry");
	} 

	struct fc_entry *entry = (struct fc_entry *)node->data;

	if (!entry) {
		return alloc_internal_error("Policy node data field is NULL");
	}

	char *type_decl_mod_name = look_up_in_decl_map(entry->context->type, DECL_TYPE);

	if (!type_decl_mod_name) {
		// If the type is not in any module, that's a different error
		// Returning success on an error condition may seem weird, but it is a
		// redundant condition with another check that will catch this if enabled.
		// Enabling this check and disabling the undeclared check is a valid (although
		// strange) configuration which will result in this condition not being logged,
		// but that is what the user has specifically requested in that situation.  The
		// more common case is having both checks on, and there we don't want to double
		// log
		return NULL;
	}

	if (strcmp(check_data->mod_name, type_decl_mod_name)) {
		struct check_result *res = malloc(sizeof(struct check_result));

		res->severity = 'S';
		res->check_id = S_ID_FC_TYPE;
		if (!asprintf(&res->message, "Type %s is declared in module %s, but used in file context here.", entry->context->type, type_decl_mod_name)) {
			free(res);
			return alloc_internal_error("Failed to generate error message in fc type checking");
		}

		return res;
	}

	return NULL;
}

struct check_result *check_file_context_roles(struct policy_node *node) {
	return NULL;
}

struct check_result *check_file_context_users(struct policy_node *node) {
	return NULL;
}

struct check_result *check_file_context_error_nodes(const struct check_data *data, const struct policy_node *node) {

	if (node->flavor != NODE_ERROR) {
		return NULL;
	}

	struct check_result *res = malloc(sizeof(struct check_result));

	res->severity = 'E';
	res->check_id = E_ID_FC_ERROR;
	if (!asprintf(&res->message, "Bad file context format")) {
		free(res);
		return alloc_internal_error("Failed to generate error message in fc error handling");
	}
	return res;
}
