/*
* Copyright 2019 Tresys Technology, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "te_checks.h"
#include "maps.h"
#include "tree.h"
#include "ordering.h"

struct check_result *check_te_order(const struct check_data *data,
                                    const struct policy_node *node)
{
	if (!data || !data->config_check_data) {
		return alloc_internal_error("Unintialized data given to C-001");
	}
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	static struct ordering_metadata *order_data;
	static unsigned int order_node_arr_index;

	switch (node->flavor) {
	case NODE_TE_FILE:
		order_data = prepare_ordering_metadata(data, node);
		order_node_arr_index = 0;
		if (!order_data) {
			return alloc_internal_error("Failed to initialize ordering for C-001");
		}
		switch (data->config_check_data->order_conf) {
		case ORDER_REF:
			calculate_longest_increasing_subsequence(node, order_data, compare_nodes_refpolicy);
			break;
		case ORDER_LAX:
			calculate_longest_increasing_subsequence(node, order_data, compare_nodes_refpolicy_lax);
			break;
		default:
			return alloc_internal_error("Unknown ordering configuration given to C-001");
		}
		break;
	case NODE_CLEANUP:
		free_ordering_metadata(order_data);
		order_data = NULL;
		break;
	default:
		if (!order_data) {
			return alloc_internal_error("Ordering data was not generated for C-001");
		}
		for (unsigned int i=order_node_arr_index; i < order_data->order_node_len; i++) {
			if (order_data->nodes[i].node == node) {
				order_node_arr_index = i;
				if (order_data->nodes[i].in_order) {
					return NULL;
				} else {
					char *reason_str = get_ordering_reason(order_data, order_node_arr_index);
					struct check_result *to_ret = make_check_result('C',
					                                                C_ID_TE_ORDER,
					                                                reason_str);
					free(reason_str);
					return to_ret;
				}
			}
		}
		return alloc_internal_error("Could not find ordering info for line");
	}
	return NULL;
}

struct check_result *check_unordered_perms_in_av_rule(__attribute__((unused)) const struct check_data *data,
                                                           const struct policy_node *node)
{
	const struct string_list *prev = NULL, *cur = node->data.av_data->perms;
	
	while (cur) {
		if (prev && strcmp(prev->string, "~") != 0 && strcmp(prev->string, cur->string) > 0) {
			return make_check_result('C', C_ID_UNORDERED_PERM,
					  "Permissions in av rule not ordered (%s before %s)",
					  prev->string,
					  cur->string);
		}
		
		prev = cur;
		cur = cur->next;
	}
	
	return NULL;
}

struct check_result *check_too_many_perms_in_allow_rule(__attribute__((unused)) const struct check_data *data,
                                                        const struct policy_node *node)
{
	// ignore multi class av rules
	if (node->data.av_data->object_classes->next) {
		return NULL;
	}
	
	// ignore non-allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}
	
	// ignore special classes
	const char *class_name = node->data.av_data->object_classes->string;
	if (strcmp(class_name, "process") == 0 ||
	    strcmp(class_name, "process2") == 0 ||
	    strcmp(class_name, "capability") == 0 ||
	    strcmp(class_name, "capability2") == 0) {
		return NULL;
	}
	
	const struct string_list *cur_perm = node->data.av_data->perms;
	unsigned short count = 0;
	
	while (cur_perm) {
		count++;
		
		cur_perm = cur_perm->next;
	}
	
	if (count > 4) {
		return make_check_result('C', C_ID_TOO_MANY_PERMS,
					 "Too many permissions (%u) for class %s in allow rule (use permission macro)",
					 count,
					 class_name);
	}
	
	return NULL;
}

struct check_result *check_multi_class_allow_rule(__attribute__((unused)) const struct check_data *data,
                                                  const struct policy_node *node)
{
	// ignore non-allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}
	
	const struct string_list *classes = node->data.av_data->object_classes;
	
	if (!classes->next) {
		return NULL;
	}
	
	const struct string_list *perms = node->data.av_data->perms;
	
	// ignore rules with a single base permission
	if (!perms->next) {
		const char *suffix = strrchr(perms->string, '_');
		if (!suffix ||
		    (0 != strcmp(suffix, "_perms"))) {
			return NULL;
		}
	}
	
	char *classes_str = join_string_list(classes);
	struct check_result *res = make_check_result('C', C_ID_MULTI_CLASS_AV_RULE,
						     "Allow rule with more than one class (%s)",
						     classes_str);	
	free(classes_str);
	return res;
}

struct check_result *check_require_block(const struct check_data *data,
                                         const struct policy_node *node)
{
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	struct policy_node *cur = node->first_child;
	while (cur) {
		if (cur->flavor != NODE_DECL) {
			cur = cur->next;
			continue;
		}
		if (cur->data.d_data->flavor != DECL_CLASS &&
		    cur->data.d_data->flavor != DECL_PERM) {
			return make_check_result('S', S_ID_REQUIRE,
			                         "Require block used in te file (use an interface call instead)");
		}
		cur = cur->next;
	}
	// Require contained only object classes and permissions
	return NULL;
}

struct check_result *check_useless_semicolon(__attribute__((unused)) const struct check_data *data,
                                             __attribute__((unused)) const struct policy_node *node)
{
	return make_check_result('S', S_ID_SEMICOLON,
	                         "Unnecessary semicolon");
}

// Helper for check_no_explicit_declaration.  Returns 1 is there is a require block
// for type_name earlier in the file, and 0 otherwise
static int has_require(const struct policy_node *node, char *type_name)
{
	const struct policy_node *cur = node;
	while (cur) {
		if (cur->flavor == NODE_REQUIRE || cur->flavor == NODE_GEN_REQ) {
			cur = cur->first_child;
			while (1) {
				if (cur->flavor == NODE_DECL && cur->data.d_data->flavor == DECL_TYPE) {
					if (0 == strcmp(type_name, cur->data.d_data->name)) {
						return 1;
					}
					struct string_list *other_types = cur->data.d_data->attrs; // In requires these
					                                                           // are types, not
					                                                           // attributes
					while (other_types) {
						if (0 == strcmp(type_name, other_types->string)) {
							return 1;
						}
						other_types = other_types->next;
					}
				}
				if (cur->next) {
					cur = cur->next;
				} else {
					break;
				}
			}
			// Not found in this require block, keep going
			cur = cur->parent;
			if (!cur) {
				break;
			}
		}
		if (cur->prev) {
			cur = cur->prev;
		} else {
			cur = cur->parent;
		}
	}
	return 0;
}


struct check_result *check_no_explicit_declaration(const struct check_data *data,
                                                   const struct policy_node *node)
{
	if (data->flavor != FILE_TE_FILE) {
		return NULL;
	}

	struct string_list *types = get_types_in_node(node);
	struct string_list *type = types;

	while (type) {
		char *mod_name = look_up_in_decl_map(type->string, DECL_TYPE);
		if (!mod_name) {
			//Not a type
			type = type->next;
			continue;
		}
		if (0 != strcmp(data->mod_name, mod_name)) {
			// It may be required
			if (!has_require(node, type->string)) {
				// We didn't find a require block with this type
				struct check_result *to_ret = make_check_result('W', W_ID_NO_EXPLICIT_DECL,
										"No explicit declaration for %s.  You should access it via interface call or use a require block.",
										type->string);
				free_string_list(types);
				return to_ret;
			}
			// Otherwise, keep checking other types in this node
		}
		type = type->next;
	}

	free_string_list(types);
	return NULL;
}

struct check_result *check_module_if_call_in_optional(const struct check_data
                                                      *data,
                                                      const struct policy_node
                                                      *node)
{

	struct if_call_data *if_data = node->data.ic_data;

	char *if_mod_name = look_up_in_ifs_map(if_data->name);

	if (!if_mod_name) {
		// Not defined as an interface.  Probably a macro
		return NULL;
	}

	if (0 == strcmp(if_mod_name, data->mod_name)) {
		// No issue calling interfaces in your own module
		return NULL;
	}

	char *mod_type = look_up_in_mods_map(if_mod_name);

	if (!mod_type || 0 != strcmp(mod_type, "module")) {
		// If mod_type is NULL, we have no info on this module.  We *should* have info
		// on all modules of type module, but in some cases may be missing ones that are
		// off or base.  Off and base pass the check.
		return NULL;
	}

	const struct policy_node *tmp = node;

	while (tmp->parent) {
		tmp = tmp->parent;
		if (tmp->flavor == NODE_OPTIONAL_POLICY) {
			return NULL;
		}
	}

	return make_check_result('W', W_ID_IF_CALL_OPTIONAL,
	                         "Call to interface defined in module should be in optional_policy block");
}

struct check_result *check_empty_if_call_arg(__attribute__((unused)) const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node)
{
	if (!node->data.ic_data->args) {
		return make_check_result('W',
					 W_ID_EMPTY_IF_CALL_ARG,
					 "Call to interface %s with empty argument",
					 node->data.ic_data->name);
	}
	
	return NULL;
}

struct check_result *check_space_if_call_arg(__attribute__((unused)) const struct
                                             check_data *data,
                                             const struct
                                             policy_node *node)
{
	const struct string_list *prev = NULL, *args = node->data.ic_data->args;
	unsigned short i = 1;
	
	while (args) {
		if (args->has_incorrect_space) {
			return make_check_result('W',
						 W_ID_SPACE_IF_CALL_ARG,
						 "Argument no. %u '%s ...' of call to interface %s contains unquoted space",
						 i - 1, // need to substract one, cause it is the next string who has the flag set
						 prev ? prev->string : "",
						 node->data.ic_data->name);
		}
		
		prev = args;
		args = args->next;
		i++;
	}
	
	return NULL;
}

struct check_result *check_declaration_interface_nameclash(__attribute__((unused)) const struct check_data
							   *data,
							   const struct policy_node
							   *node)
{
	const char *decl_name = node->data.d_data->name;

	if (look_up_in_ifs_map(decl_name)) {
		return make_check_result('E', E_ID_DECL_IF_CLASH,
				  "Declaration with name %s clashes with same named interface",
				  decl_name);
	}

	return NULL;
}
