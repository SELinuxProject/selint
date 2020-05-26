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
#include "util.h"
#include "perm_macro.h"

struct check_result *check_te_order(const struct check_data *data,
                                    const struct policy_node *node)
{
	if (!data || !data->config_check_data) {
		return alloc_internal_error("Uninitialized data given to C-001");
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
					                                                "%s",
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

struct check_result *check_unordered_perms(__attribute__((unused)) const struct check_data *data,
                                           const struct policy_node *node)
{
	const struct string_list *prev = NULL, *cur = NULL;
	const char *flavor;
	if (node->flavor == NODE_AV_RULE) {
		cur = node->data.av_data->perms;
		flavor = "av rule";
	} else if (node->flavor == NODE_DECL) {
		// ignore non-class declarations
		if (node->data.d_data->flavor != DECL_CLASS) {
			return NULL;
		}
		cur = node->data.d_data->attrs;
		flavor = "class declaration";
	} else {
		return alloc_internal_error("Invalid node type for `check_unordered_perms`");
	}

	while (cur) {
		if (prev && strcmp(prev->string, "~") != 0) {
			const int compare = strcmp(prev->string, cur->string);

			if (compare > 0) {
				return make_check_result('C', C_ID_UNORDERED_PERM,
			                                 "Permissions in %s not ordered (%s before %s)",
			                                 flavor,
			                                 prev->string,
			                                 cur->string);
			} else if (compare == 0) {
				return make_check_result('C', C_ID_UNORDERED_PERM,
			                                 "Permissions in %s repeated (%s)",
			                                 flavor,
			                                 cur->string);
			}
		}

		prev = cur;
		cur = cur->next;
	}

	return NULL;

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

struct check_result *check_bare_module_statement(__attribute__((unused)) const struct check_data *data,
                                                 const struct policy_node *node)
{
	if (node->data.h_data->flavor == HEADER_BARE) {
		return make_check_result('S', S_ID_BARE_MODULE,
	                                 "Bare module statement (use `policy_module()` instead)");
	}

	return NULL;
}

// check if '$STR' ends with '$SUFFIX_perms'
static bool ends_with_suffix_perms(const char *str, size_t str_len, const char *suffix, size_t suffix_len)
{
	if (str_len < (suffix_len + strlen("_perms"))) {
		return 0;
	}

	// no need to check last 6 characters are actual '_perms'
	// we call this only on strings we have checked to have this suffix
	return (0 == strncmp(str + str_len - (suffix_len + strlen("_perms")), suffix, suffix_len));
}

struct check_result *check_perm_macro_class_mismatch(__attribute__((unused)) const struct check_data *data,
                                                     const struct policy_node *node)
{
	static const char *const class_aliases[][2] = {
		{ "chr_file", "term"   },
		{ "process",  "signal" },
	};

	static const char *const file_suffix_classes[] = {
		"lnk_file",
		"chr_file",
		"blk_file",
		"sock_file",
		"fifo_file",
	};

	const char *class_name = node->data.av_data->object_classes->string;
	const size_t class_name_len = strlen(class_name);

	// ignore multi class av rules
	if (node->data.av_data->object_classes->next ||
	    ends_with(class_name, class_name_len, "_class_set", strlen("_class_set"))) {
		return NULL;
	}

	const char *class_alias = NULL;
	for (size_t i = 0; i < (sizeof class_aliases / sizeof *class_aliases); ++i) {
		if (0 == strcmp(class_name, class_aliases[i][0])) {
			class_alias = class_aliases[i][1];
			break;
		}
	}
	const size_t class_alias_len = class_alias ? strlen(class_alias) : 0;
	const bool is_file_class = (0 == strcmp(class_name, "file"));
	const bool is_netlink_socket_class = (0 == strncmp(class_name, "netlink_", strlen("netlink_")));
	const bool is_socket_class = ends_with(class_name, class_name_len, "_socket", strlen("_socket"));

	for (const struct string_list *perms = node->data.av_data->perms; perms; perms = perms->next) {
		const size_t perm_len = strlen(perms->string);

		// ignore permissions without '_perms' suffix; they are probably not macros
		if (!ends_with(perms->string, perm_len, "_perms", strlen("_perms"))) {
			continue;
		}

		// ignore permissions matching 'something[_something]_$CLASSNAME_perms'
		if (ends_with_suffix_perms(perms->string, perm_len, class_name, class_name_len)) {
			// report usage of macros matching different class with actual class as suffix
			// e.g. report 'something_fifo_file_perms' for class 'file'
			if (is_file_class) {
				for (size_t i = 0; i < (sizeof file_suffix_classes / sizeof *file_suffix_classes); ++i) {
					if (ends_with_suffix_perms(perms->string, perm_len, file_suffix_classes[i], strlen(file_suffix_classes[i]))) {
						goto report;
					}
				}
			}
			continue;
		}

		// ignore permissions 'something[_something]_netlink_socket_perms' for netlink classes
		if (is_netlink_socket_class &&
		    ends_with(perms->string, perm_len, "_socket_perms", strlen("_socket_perms"))) {
			continue;
		}

		// ignore permissions 'something[_something]_socket_perms' for (non-netlink) socket classes
		if (is_socket_class &&
		    !is_netlink_socket_class &&
		    ends_with(perms->string, perm_len, "_socket_perms", strlen("_socket_perms")) &&
		    !ends_with(perms->string, perm_len, "netlink_socket_perms", strlen("netlink_socket_perms"))) {
			continue;
		}

		// ignore permissions 'something[_something]_$CLASSNAMEALIAS_perms'
		if (class_alias && ends_with_suffix_perms(perms->string, perm_len, class_alias, class_alias_len)) {
			continue;
		}

report:
		return make_check_result('S', S_ID_PERM_SUFFIX,
					 "Permission macro %s does not match class %s",
					 perms->string,
					 class_name);
	}

	return NULL;
}

struct check_result *check_perm_macro_available(__attribute__((unused)) const struct check_data *data,
                                                const struct policy_node *node)
{
	// ignore non allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}

	// ignore multi class av rules
	const struct string_list *class = node->data.av_data->object_classes;
	if (class->next ||
	    ends_with(class->string, strlen(class->string), "_class_set", strlen("_class_set"))) {
		return NULL;
	}

	char *check_str = permmacro_check(node->data.av_data->object_classes->string,
					  node->data.av_data->perms);
	if (!check_str) {
		return NULL;
	}

	struct check_result *res = make_check_result('S', S_ID_PERMMACRO,
						"%s",
						check_str);
	free(check_str);
	return res;
}

// Helper for check_no_explicit_declaration.  Returns 1 is there is a require block
// for name earlier in the file, and 0 otherwise
static int has_require(const struct policy_node *node, const char *name, enum decl_flavor flavor)
{
	const struct policy_node *cur = node;
	while (cur) {
		if (cur->flavor == NODE_REQUIRE || cur->flavor == NODE_GEN_REQ) {
			cur = cur->first_child;
			while (1) {
				if (cur->flavor == NODE_DECL && cur->data.d_data->flavor == flavor) {
					if (0 == strcmp(name, cur->data.d_data->name)) {
						return 1;
					}
					struct string_list *other_types = cur->data.d_data->attrs; // In requires these
					                                                           // are types, not
					                                                           // attributes
					while (other_types) {
						if (0 == strcmp(name, other_types->string)) {
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

	struct string_list *names = get_names_in_node(node);

	for (const struct string_list *name = names; name; name = name->next) {
		const char *mod_name;
		enum decl_flavor flavor;

		if ((mod_name = look_up_in_decl_map(name->string, DECL_TYPE))) {
			flavor = DECL_TYPE;
		} else if ((mod_name = look_up_in_decl_map(name->string, DECL_ATTRIBUTE))) {
			flavor = DECL_ATTRIBUTE;
		} else if ((mod_name = look_up_in_decl_map(name->string, DECL_ATTRIBUTE_ROLE))) {
			flavor = DECL_ATTRIBUTE_ROLE;
		// Do not check for roles: in refpolicy they are defined in the kernel module
		// and used in role modules (like unprivuser)
		} else {
			//Not a known name
			continue;
		}

		if (0 != strcmp(data->mod_name, mod_name)) {
			// It may be required
			if (!has_require(node, name->string, flavor)) {
				// We didn't find a require block with this name
				struct check_result *to_ret = make_check_result('W', W_ID_NO_EXPLICIT_DECL,
										"No explicit declaration for %s from module %s.  You should access it via interface call or use a require block.",
										name->string, mod_name);
				free_string_list(names);
				return to_ret;
			}
			// Otherwise, keep checking other names in this node
		}
	}

	free_string_list(names);
	return NULL;
}

struct check_result *check_module_if_call_in_optional(const struct check_data
                                                      *data,
                                                      const struct policy_node
                                                      *node)
{

	const struct if_call_data *if_data = node->data.ic_data;

	const char *if_mod_name = look_up_in_ifs_map(if_data->name);

	if (!if_mod_name) {
		// Not defined as an interface.  Probably a macro
		return NULL;
	}

	if (0 == strcmp(if_mod_name, data->mod_name)) {
		// No issue calling interfaces in your own module
		return NULL;
	}

	const char *mod_type = look_up_in_mods_map(if_mod_name);

	if (!mod_type) {
		// If mod_type is NULL, we have no info on this module.  We *should* have info
		// on all modules of type module, but in some cases may be missing ones that are
		// off or base.  Off and base pass the check.
		return NULL;
	}

	if (0 == strcmp(mod_type, "base")) {
		// No issue calling interfaces in base module
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
	                         "Call to interface %s defined in module %s should be in optional_policy block",
	                         if_data->name,
	                         if_mod_name);
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
			// do not issue on mls ranges
			if (prev &&
			    (args->string[0] != '-' ||
			    look_up_in_decl_map(prev->string, DECL_TYPE) ||
			    look_up_in_decl_map(prev->string, DECL_ATTRIBUTE) ||
			    look_up_in_decl_map(prev->string, DECL_ROLE) ||
			    look_up_in_decl_map(prev->string, DECL_ATTRIBUTE_ROLE) ||
			    look_up_in_decl_map(prev->string, DECL_USER))) {

				return make_check_result('W',
							 W_ID_SPACE_IF_CALL_ARG,
							 "Argument no. %u '%s ...' of call to interface %s contains unquoted space",
							 i - 1, // need to subtract one, cause it is the next string who has the flag set
							 prev->string,
							 node->data.ic_data->name);
			}
		} else {
			i++;
		}

		prev = args;
		args = args->next;
	}

	return NULL;
}

struct check_result *check_risky_allow_perm(__attribute__((unused)) const struct
                                            check_data *data,
                                            const struct
                                            policy_node *node)
{
	// ignore non-allow rules
	if (node->data.av_data->flavor != AV_RULE_ALLOW) {
		return NULL;
	}

	const struct string_list *perms = node->data.av_data->perms;

	while (perms) {
		if (0 == strcmp(perms->string, "*") ||
		    0 == strcmp(perms->string, "~")) {
			return make_check_result('W', W_ID_RISKY_ALLOW_PERM,
						 "Allow rule with complement or wildcard permission");
		}

		perms = perms->next;
	}

	return NULL;
}

struct check_result *check_module_file_name_mismatch(const struct check_data
						     *data,
						     const struct policy_node
						     *node)
{
	const char *mod_name = node->data.h_data->module_name;
	size_t mod_name_len = strlen(mod_name);
	const char *file_name = data->filename;
	size_t file_name_len = strlen(file_name);

	const char *file_name_ext = strrchr(file_name, '.');
	if (file_name_ext) {
		file_name_len -= strlen(file_name_ext);
	}

	if (mod_name_len != file_name_len || strncmp(mod_name, file_name, file_name_len)) {
		return make_check_result('W', W_ID_MOD_NAME_FILE,
					 "Module name %s does not match file name %s",
					 mod_name,
					 file_name);
	}

	return NULL;
}

static bool starts_with_module_prefix(const char *name)
{
	for (const char *prefix = strchr(name, '_'); prefix; prefix = strchr(prefix + 1, '_')) {
		char *search_mod = strndup(name, (size_t)(prefix - name));
		if (look_up_in_mods_map(search_mod)) {
			free(search_mod);
			return true;
		}

		for (size_t i = 0; i < (sizeof RefPol_module_abbreviations / sizeof *RefPol_module_abbreviations); ++i) {
			if (0 == strcmp(search_mod, RefPol_module_abbreviations[i][0]) &&
			    look_up_in_mods_map(RefPol_module_abbreviations[i][1])) {
				free(search_mod);
				return true;
			}
		}

		free(search_mod);
	}

	return false;
}

struct check_result *check_unknown_interface_call(__attribute__((unused)) const struct check_data
						  *data,
						  const struct policy_node
						  *node)
{
	const char *if_name = node->data.ic_data->name;

	// ignore known macros starting with module name
	for (size_t i = 0; i < (sizeof RefPol_macros_with_module_prefix / sizeof *RefPol_macros_with_module_prefix); ++i) {
		if (0 == strcmp(if_name, RefPol_macros_with_module_prefix[i])) {
			return NULL;
		}
	}

	// ignore calls which does not start with a module name: they are probably macros
	if (!starts_with_module_prefix(if_name)) {
		return NULL;
	}

	// ignore known interfaces
	if (look_up_in_ifs_map(if_name)) {
		return NULL;
	}

	return make_check_result('W', W_ID_UNKNOWN_CALL,
				 "Call to %s can not be referenced to any interface",
				 if_name);
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

struct check_result *check_unknown_permission_macro(__attribute__((unused)) const struct check_data
						    *data,
						    const struct policy_node
						    *node)
{
	static unsigned int permmacros_count = (unsigned int)-1;

	if (permmacros_count == (unsigned int)-1) {
		permmacros_count = permmacros_map_count();
	}

	// ignore if no permission macro was parsed
	if (permmacros_count == 0) {
		return NULL;
	}

	for (const struct string_list *cur = node->data.av_data->perms; cur; cur = cur->next) {
		// ignore permissions without '_perms' suffix; they are probably not macros
		if (!ends_with(cur->string, strlen(cur->string), "_perms", strlen("_perms"))) {
			continue;
		}

		// ignore generated all_ permission macros
		if (0 == strncmp(cur->string, "all_", strlen("all_"))) {
			continue;
		}

		if (look_up_in_permmacros_map(cur->string)) {
			continue;
		}

		return make_check_result('E', E_ID_UNKNOWN_PERMMACRO,
					 "Unknown permission macro %s used",
					 cur->string);
	}

	return NULL;
}

struct check_result *check_block_contains_invalid_statement(__attribute__((unused)) const struct check_data
							    *data,
							    const struct policy_node
							    *node)
{
	const char *stmt_kind = NULL;
	const char *stmt_extra_info = NULL;
	const char *block_kind = NULL;

	// Note: require blocks are parsed specially and only contain supported statements by the grammar

	switch(node->flavor) {
	case NODE_DECL:
		switch(node->data.d_data->flavor) {
		case DECL_TYPE:
			stmt_kind = "type declaration";
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			// declarations in optional blocks seem to work, but might work inconsistently
			//else if (node->nested & NESTED_OPTIONAL && !(node->nested & NESTED_REQUIRE)) {
			//	block_kind = "optional";
			//}
			break;
		case DECL_ATTRIBUTE:
			stmt_kind = "type attribute declaration";
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			break;
		case DECL_ROLE:
			stmt_kind = "role declaration";
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			break;
		case DECL_ATTRIBUTE_ROLE:
			stmt_kind = "role attribute declaration";
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			break;
		case DECL_BOOL:
			stmt_kind = "boolean declaration";
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			break;
		case DECL_CLASS:
		case DECL_PERM:
		case DECL_USER:
			break;
		}
		break;
	case NODE_TYPE_ATTRIBUTE:
		stmt_kind = "type attribute";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_TYPE_ALIAS:
		stmt_kind = "type alias";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_PERMISSIVE:
		stmt_kind = "permissive";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_ROLE_ATTRIBUTE:
		stmt_kind = "role attribute";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_ROLE_ALLOW:
		stmt_kind = "role allow";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_RT_RULE:
		stmt_kind = "role transition";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_ROLE_TYPES:
		stmt_kind = "role transition";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_TUNABLE_POLICY:
		stmt_kind = "tunable block";
		if (node->nested & NESTED_CONDITIONAL) {
			block_kind = "conditional";
		}
		break;
	case NODE_IF_CALL:
		if (look_up_in_template_map(node->data.ic_data->name)) {
			stmt_kind = "template call";
			stmt_extra_info = node->data.ic_data->name;
			if (node->nested & NESTED_CONDITIONAL) {
				block_kind = "conditional";
			}
			// declarations in optional blocks seem to work, but might work inconsistently
			//else if (node->nested & NESTED_OPTIONAL) {
			//	block_kind = "optional";
			//}
		}
		break;

	// the following flavors are not constrained (except maybe from require blocks - see note above)
	case NODE_TT_RULE:
	case NODE_AV_RULE:
	case NODE_OPTIONAL_POLICY:
	case NODE_OPTIONAL_ELSE:
	case NODE_GEN_REQ:
	case NODE_REQUIRE:
		return NULL;

	// the following flavors are not real policy statements and therefore not constrained
	case NODE_TE_FILE:
	case NODE_IF_FILE:
	case NODE_FC_FILE:
	case NODE_SPT_FILE:
	case NODE_HEADER:
	case NODE_ALIAS:
	case NODE_M4_CALL:
	case NODE_IFDEF:
	case NODE_START_BLOCK:
	case NODE_COMMENT:
	case NODE_EMPTY:
	case NODE_SEMICOLON:
	case NODE_M4_ARG:
	case NODE_INTERFACE_DEF:
	case NODE_TEMP_DEF:
	case NODE_FC_ENTRY:
	case NODE_CLEANUP:
	case NODE_ERROR:
		return NULL;

	//default:
	//	return alloc_internal_error("Invalid node given to E-008");
	}

	if (!stmt_kind || !block_kind) {
		return NULL;
	}

	return make_check_result('E', E_ID_BLOCK_INV_STMT,
				 "Invalid %s%s%s in %s block",
				 stmt_kind,
				 stmt_extra_info ? " " : "",
				 stmt_extra_info ? stmt_extra_info : "",
				 block_kind);
}
