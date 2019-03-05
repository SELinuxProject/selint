#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "if_checks.h"
#include "tree.h"

#define NOT_REQ_MESSAGE "%s %s is used in interface but not required"

struct check_result *check_interface_definitions_have_comment(const struct check_data *data, const struct policy_node *node) {
	if (node->flavor != NODE_IF_DEF && node->flavor != NODE_TEMP_DEF) {
		return alloc_internal_error("Interface comment check called on non interface definition entry");
	}

	if (!(node->prev) || node->prev->flavor != NODE_COMMENT) {
		return make_check_result('C', C_ID_IF_COMMENT, "No comment before interface definition for %s", (char*) node->data);

	} else {
		return NULL;
	}
}

struct check_result *check_type_used_but_not_required_in_if(const struct check_data *data, const struct policy_node *node) {


	const struct policy_node *cur = node;

	struct string_list *types_in_current_node = get_types_in_node(node); 

	if (!types_in_current_node) {
		return NULL;
	}

	while (cur) {
		if (cur->flavor == NODE_IF_DEF || cur->flavor == NODE_TEMP_DEF) {
			break;
		}
		cur = cur->parent;
	}

	if (!cur) {
		free_string_list(types_in_current_node);
		return NULL;
	}

	// In a template or interface, and cur is a pointer to the definition node

	cur = cur->first_child;

	while (cur && cur != node && (cur->flavor != NODE_GEN_REQ && cur->flavor != NODE_REQUIRE)) {
		cur = cur->next;
	}

	struct string_list *types_required;
	if (!cur || cur == node) {
		types_required = NULL;
	} else {
		types_required = get_types_required(cur);
	}

	struct string_list *type_node = types_in_current_node;

	while (type_node) {
		if ((strcmp(type_node->string, "self") != 0) &&
			!index(type_node->string, '$') &&
			!str_in_sl(type_node->string, types_required)) {
			struct check_result *res = make_check_result('W', W_ID_NO_REQ, NOT_REQ_MESSAGE, "Type", type_node->string);
			free_string_list(types_in_current_node);
			free_string_list(types_required);
			return res;
		}
		type_node = type_node->next;
	}

	free_string_list(types_in_current_node);
	free_string_list(types_required);

	return NULL;
}
