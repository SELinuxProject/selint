#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "if_checks.h"
#include "tree.h"


struct check_result *check_interface_definitions_have_comment(const struct check_data *data, const struct policy_node *node) {
	if (node->flavor != NODE_IF_DEF && node->flavor != NODE_TEMP_DEF) {
		return alloc_internal_error("Interface comment check called on non interface definition entry");
	}

	if (!(node->prev) || node->prev->flavor != NODE_COMMENT) {
		struct check_result *res = malloc(sizeof(struct check_result));
		res->severity = 'C';
		res->check_id = C_IF_COMMENT;
		if (!asprintf(&res->message, "No comment before interface definition for %s", (char*) node->data)) {
			free(res);
			return alloc_internal_error("Failed to generate error message in interface comment checking");
		}
		return res;
	} else {
		return NULL;
	}
}

struct check_result *type_used_but_not_required_in_if(const struct check_data *data, const struct policy_node *node) {
	return NULL;
}
