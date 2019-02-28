#include <stddef.h>
#include <stdlib.h>

#include "if_checks.h"
#include "tree.h"


struct check_result *check_interface_definitions_have_comment(const struct check_data *data, const struct policy_node *node) {
	if (node->flavor != NODE_IF_DEF && node->flavor != NODE_TEMP_DEF) {
		return alloc_internal_error("Interface comment check called on non interface definition entry");
	}

	if (!(node->prev) || node->prev->flavor != NODE_COMMENT) {
		return make_check_result('C', C_IF_COMMENT, "No comment before interface definition for %s", (char*) node->data);
	} else {
		return NULL;
	}
}

struct check_result *type_used_but_not_required_in_if(const struct check_data *data, const struct policy_node *node) {
	return NULL;
}
