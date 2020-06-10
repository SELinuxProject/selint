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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ordering.h"
#include "maps.h"

int is_optional(const struct policy_node *node);
int is_tunable(const struct policy_node *node);
int is_in_ifdef(const struct policy_node *node);

struct ordering_metadata *prepare_ordering_metadata(const struct check_data *data, const struct policy_node *head)
{
	const struct policy_node *cur = head->next; // head is file.  Order the contents
	size_t count = 0;
	struct section_data *sections = calloc(1, sizeof(struct section_data));

	while (cur) {
		if (add_section_info(sections, get_section(cur), cur->lineno) == SELINT_BAD_ARG) {
			free(sections);
			return NULL;
		}
		count += 1;
		cur = dfs_next(cur);
	}
	calculate_average_lines(sections);

	struct ordering_metadata *ret = calloc(1, sizeof(struct ordering_metadata) +
	                                       (count * sizeof(struct order_node)));
	ret->mod_name = data->mod_name; // Will only be needed for duration of check, so will remain allocated
	                                // until we are done with this copy
	ret->order_node_len = count;
	ret->sections = sections;
	// The nodes array will be populated during the LIS traversal
	return ret;
}

void calculate_longest_increasing_subsequence(const struct policy_node *head,
                                              struct ordering_metadata *ordering,
                                              enum order_difference_reason (*comp_func)(struct ordering_metadata *o,
                                                                                        const struct policy_node *first,
                                                                                        const struct policy_node *second))
{
	struct order_node *nodes = ordering->nodes;
	int longest_seq = 0;
	int index = 0;

	struct policy_node *cur = head->next;

	while (cur) {
		// Save the node in the array
		if (cur->flavor == NODE_START_BLOCK) {
			cur = dfs_next(cur);
			continue;
		}
		nodes[index].node = cur;

		// binary search sequences so far
		int low = 1;
		int high = longest_seq;
		while (low <= high) {
			int mid = (low + high + 1) / 2; // Ceiling
			if (comp_func(ordering, nodes[nodes[mid-1].end_of_seq].node, nodes[index].node) >= 0) {
				low = mid + 1;
			} else {
				high = mid - 1;
			}
		}

		// Now low should be 1 greater than the length of the longest
		// sequence that ends lower than the current number
		if (low <= 1) {
			nodes[index].seq_prev = -1; // No previous node
		} else {
			nodes[index].seq_prev = nodes[low - 2].end_of_seq;
		}
		nodes[low - 1].end_of_seq = index;

		if (low > longest_seq) {
			longest_seq = low;
		}
		index++;
		cur = dfs_next(cur);
	}

	// Mark LIS elements
	index = nodes[longest_seq - 1].end_of_seq;
	while (index != -1) {
		nodes[index].in_order = 1;
		index = nodes[index].seq_prev;
	}

#ifdef DEBUG_INFO
	for (int i=0; i< ordering->order_node_len; i++) {
		if(nodes[i].node) {
			printf("Line: %u, Section %s: LSS: %d\n",
			       nodes[i].node->lineno,
			       get_section(nodes[i].node),
			       get_local_subsection(ordering->mod_name, nodes[i].node));
		}
	}
#endif
}

enum selint_error add_section_info(struct section_data *sections,
                                   const char *section_name,
                                   unsigned int lineno)
{
	if (sections == NULL || section_name == NULL) {
		return SELINT_BAD_ARG;
	}
	struct section_data *cur = sections;
	if (sections->section_name != NULL) {
		while (0 != strcmp(cur->section_name, section_name)) {
			if (cur->next == NULL) {
				cur->next = calloc(1, sizeof(struct section_data));
				cur = cur->next;
				break;
			}
			cur = cur->next;
		}
	}
	// cur is now the appropriate section_data node.  If section_name is
	// NULL, then this is a new node
	if (!cur->section_name) {
		cur->section_name = strdup(section_name);
	}

	cur->lineno_count++;
	cur->lines_sum += lineno;
	return SELINT_SUCCESS;
}

const char *get_section(const struct policy_node *node)
{
	if (!node) {
		return NULL; //Error
	}

	switch (node->flavor) {
	case NODE_TE_FILE:
	case NODE_IF_FILE:
	case NODE_FC_FILE:
	case NODE_SPT_FILE:
		return NULL; // Should never happen
	case NODE_HEADER:
		return "_non_ordered"; // Guaranteed at top by grammar
	case NODE_AV_RULE:
		if (node->data.av_data->flavor == AV_RULE_NEVERALLOW) {
			// These are somewhat of a unique situation, and the style guide
			// doesn't mention them explicitly.  Maybe they should just group
			// like other av rules, but they can often have multiple types.
			// Additionally, the below code assumes that the first string in
			// the sources is a type or attribute, but in the case of neverallows
			// it can be "~"
			return "_non_ordered";
		}
		if (node->data.av_data->flavor == AV_RULE_AUDITALLOW) {
			return "_non_ordered";
		}
		if (node->data.av_data->perms &&
		    (str_in_sl("associate", node->data.av_data->perms) ||
		     str_in_sl("mounton", node->data.av_data->perms))) {
			return "_non_ordered"; // Can be transform or with rules
		}
		// The case of multiple source types is weird.  For now
		// just using the first one seems fine.
		return node->data.av_data->sources->string;
	case NODE_TT_RULE:
		// TODO: Are type_member and type_change the same as tt
		// from an ordering standpoint?
		// The case of multiple source types is weird.  For now
		// just using the first one seems fine.
		return node->data.av_data->sources->string;
	case NODE_RT_RULE:
		return "_non_ordered";
	case NODE_ROLE_ALLOW:
	case NODE_ROLE_TYPES:
		// These are not in the style guide. I normally see them grouped
		// with declarations, but maybe a future ordering configuration
		// can sort them that way
		return "_non_ordered";
	case NODE_DECL:
	case NODE_ALIAS:
	case NODE_TYPE_ALIAS:
	case NODE_TYPE_ATTRIBUTE:
	case NODE_ROLE_ATTRIBUTE:
		if (is_in_require(node)) {
			return "_non_ordered";
		} else {
			return "_declarations";
		}
	case NODE_M4_CALL:
		return "_non_ordered"; // TODO: It's probably way more
	// complicated than this
	case NODE_OPTIONAL_POLICY:
	case NODE_OPTIONAL_ELSE:
	case NODE_TUNABLE_POLICY:
	case NODE_IFDEF:
		return get_section(node->first_child);
	case NODE_M4_ARG:
		return "_non_ordered"; //TODO
	case NODE_START_BLOCK:
		if (node->next) {
			return get_section(node->next);
		} else {
			return "_non_ordered"; // empty block
		}
	case NODE_IF_CALL:
		// check for filetrans_if first to treat interfaces with the
		// flags filetrans and transform as _non-ordered
		if (is_filetrans_if(node->data.ic_data->name)) {
			return "_non_ordered";
		} else if (!is_optional(node) &&
		    !is_in_ifdef(node) &&
		    !is_tunable(node) &&
		    (look_up_in_template_map(node->data.ic_data->name) ||
		     is_transform_if(node->data.ic_data->name) ||
		     is_role_if(node->data.ic_data->name))) {
			return "_declarations";
		} else {
			if (node->data.ic_data->args) {
				return node->data.ic_data->args->string;
			} else {
				// Empty interface call
				return "_non_ordered";
			}
		}
	case NODE_TEMP_DEF:
	case NODE_INTERFACE_DEF:
		return NULL;           // if files only
	case NODE_REQUIRE:
	case NODE_GEN_REQ:
		return "_non_ordered"; // Not in style guide
	case NODE_PERMISSIVE:
		return "_non_ordered"; // Not in style guide
	case NODE_FC_ENTRY:
		return NULL;           // fc files only
	case NODE_COMMENT:
	case NODE_EMPTY:
	case NODE_SEMICOLON:
	case NODE_ERROR:
		return "_non_ordered";
	default:
		// Should never happen
		return NULL;
	}
}

void calculate_average_lines(struct section_data *sections)
{
	while (sections) {
		sections->avg_line = (float)sections->lines_sum / (float)sections->lineno_count;
		sections = sections->next;
	}
}

float get_avg_line_by_name(const char *section_name, struct section_data *sections)
{
	while (0 != strcmp(sections->section_name, section_name)) {
		sections = sections->next;
		if (!sections) {
			return -1; //Error
		}
	}
	return sections->avg_line;
}

static int is_self_rule(const struct policy_node *node)
{
	return node->flavor == NODE_AV_RULE &&
	       node->data.av_data &&
	       node->data.av_data->targets &&
	       0 == strcmp(node->data.av_data->targets->string, "self");
}

static int is_own_module_rule(const struct policy_node *node, const char *current_mod_name)
{
	if (node->flavor != NODE_AV_RULE &&
	    node->flavor != NODE_IF_CALL) {
		return 0;
	}

	if (node->flavor == NODE_IF_CALL) {
		// These should actually be patterns, not real calls
		if (look_up_in_ifs_map(node->data.ic_data->name)) {
			return 0;
		}
	}
	struct string_list *names = get_names_in_node(node);
	struct string_list *cur = names;
	while (cur) {
		const char *module_of_type_or_attr = look_up_in_decl_map(cur->string, DECL_TYPE);
		if (!module_of_type_or_attr) {
			module_of_type_or_attr = look_up_in_decl_map(cur->string, DECL_ATTRIBUTE);
		}
		if (module_of_type_or_attr &&
		    0 != strcmp(module_of_type_or_attr, current_mod_name)) {
			free_string_list(names);
			return 0;
		}
		cur = cur->next;
	}
	free_string_list(names);
	// This assumes that not found strings are not types from other modules.
	// This is probably necessary because we'll find strings like "file" or
	// "read_file_perms" for example.  However, in normal mode without context
	// this could definitely be a problem because we won't find types from
	// other modules
	return 1;
}

static int is_kernel_mod_if_call(const struct policy_node *node)
{
	if (node->flavor != NODE_IF_CALL) {
		return 0;
	}
	const char *mod_name = look_up_in_ifs_map(node->data.ic_data->name);
	if (!mod_name) {
		return 0;
	}
	if (0 == strcmp("kernel", mod_name)) {
		return 1;
	}
	return 0;
}

static int is_own_mod_if_call(const struct policy_node *node, const char *current_mod_name)
{
	if (node->flavor != NODE_IF_CALL) {
		return 0;
	}
	const char *mod_name = look_up_in_ifs_map(node->data.ic_data->name);
	if (!mod_name) {
		return 0;
	}

	if (current_mod_name &&
	    0 != strcmp(current_mod_name, mod_name)) {
		return 0;
	}
	return 1;
}

static int check_call_layer(const struct policy_node *node, const char *layer_to_check)
{
	if (node->flavor != NODE_IF_CALL) {
		return 0;
	}
	const char *mod_name = look_up_in_ifs_map(node->data.ic_data->name);
	if (!mod_name) {
		// not an actual interface
		return 0;
	}
	const char *layer_name = look_up_in_mod_layers_map(mod_name);
	if (!layer_name) {
		return 0;
	}
	return (0 == strcmp(layer_name, layer_to_check));
}

static int is_kernel_layer_if_call(const struct policy_node *node)
{
	return check_call_layer(node, "kernel");
}

static int is_system_layer_if_call(const struct policy_node *node)
{
	return check_call_layer(node, "system");
}

int is_optional(const struct policy_node *node)
{
	int ret = 0;
	while (node) {
		if (node->flavor == NODE_OPTIONAL_POLICY ||
		    node->flavor == NODE_OPTIONAL_ELSE) {
			ret = 1;
		} else if (node->flavor == NODE_TUNABLE_POLICY ||
		           node->flavor == NODE_IFDEF) {
			ret = 0;
		}
		node = node->parent;
	}
	return ret;
}

int is_tunable(const struct policy_node *node)
{
	int ret = 0;
	while (node) {
		if (node->flavor == NODE_TUNABLE_POLICY) {
			ret = 1;
		} else if (node->flavor == NODE_OPTIONAL_POLICY ||
		           node->flavor == NODE_OPTIONAL_ELSE ||
		           node->flavor == NODE_IFDEF) {
			ret = 0;
		}
		node = node->parent;
	}
	return ret;
}

int is_in_ifdef(const struct policy_node *node)
{
	int ret = 0;
	while (node) {
		if (node->flavor == NODE_IFDEF) {
			ret = 1;
		} else if (node->flavor == NODE_OPTIONAL_POLICY ||
		           node->flavor == NODE_OPTIONAL_ELSE ||
		           node->flavor == NODE_TUNABLE_POLICY) {
			ret = 0;
		}

		node = node->parent;
	}
	return ret;
}

enum local_subsection get_local_subsection(const char *mod_name, const struct policy_node *node)
{
	if (!node) {
		return LSS_UNKNOWN;
	}
	if (is_in_ifdef(node)) {
		return LSS_BUILD_OPTION;
	} else if (is_optional(node)) {
		return LSS_OPTIONAL;
	} else if (is_tunable(node)) {
		return LSS_TUNABLE;
	} else if (is_self_rule(node)) {
		return LSS_SELF;
	} else if (is_own_module_rule(node, mod_name)) {
		return LSS_OWN;
	} else if (is_own_mod_if_call(node, mod_name)) {
		return LSS_OWN;
	} else if (is_kernel_mod_if_call(node)) {
		return LSS_KERNEL_MOD;
	} else if (is_kernel_layer_if_call(node)) {
		return LSS_KERNEL;
	} else if (is_system_layer_if_call(node)) {
		return LSS_SYSTEM;
	} else if (node->flavor == NODE_IF_CALL) {
		return LSS_OTHER;
	} else {
		// TODO conditional, optional etc
		return LSS_UNKNOWN;
	}
}

/*
 * Treat the following as the same section:
 *       foo_t and foo_r
 *       foo   and foo_t
 *       foo   and foo_r
 */
static int is_same_section(const char *first_section_name, const char *second_section_name)
{
	size_t first_length = strlen(first_section_name);
	size_t second_length = strlen(second_section_name);


	if (first_length >= 3 &&
	    (first_section_name[first_length-1] == 't' || first_section_name[first_length-1] == 'r') &&
	    first_section_name[first_length-2] == '_') {
		first_length -= 2;
	}
	if (second_length >= 3 &&
	    (second_section_name[second_length-1] == 't' || second_section_name[second_length-1] == 'r') &&
	    second_section_name[second_length-2] == '_') {
		second_length -= 2;
	}

	return (0 == strncmp(first_section_name, second_section_name, first_length > second_length ? first_length : second_length));
}

#define CHECK_ORDERING(to_check_first, to_check_second, comp, ret) \
	if (to_check_first == comp) { \
		return ret; \
	} \
	if (to_check_second == comp) { \
		return -ret; \
	} \
// Call this in order of an ordering on enums.  It returns a positive or
// negative value based on which one it encounters first.
#define CHECK_FLAVOR_ORDERING(data_flavor, comp, ret) \
	CHECK_ORDERING(first->data.data_flavor->flavor, second->data.data_flavor->flavor, comp, ret)

enum order_difference_reason compare_nodes_refpolicy_generic(struct ordering_metadata *ordering_data,
                                                             const struct policy_node *first,
                                                             const struct policy_node *second,
						             enum order_conf variant)
{
	const char *first_section_name = get_section(first);
	const char *second_section_name = get_section(second);

	if (first_section_name == NULL || second_section_name == NULL) {
		return ORDERING_ERROR;
	}

	if (0 == strcmp(first_section_name, "_non_ordered") ||
	    0 == strcmp(second_section_name, "_non_ordered")) {
		return ORDER_EQUAL;
	}

	if (!is_same_section(first_section_name, second_section_name)) {
		if (0 != strcmp(first_section_name, "_declarations") &&
		    (0 == strcmp(second_section_name, "_declarations") ||
		     (get_avg_line_by_name(first_section_name, ordering_data->sections) >
		      get_avg_line_by_name(second_section_name, ordering_data->sections))) &&
		    // allow raw section alphabetically following another raw section
		    (!(first_section_name[0] != '_' && second_section_name[0] != '_' && strcmp(first_section_name, second_section_name) < 0))) {
			return -ORDER_SECTION;
		} else {
			return ORDER_SECTION;
		}
	}

	// If we made it to this point the two nodes are in the same section

	if (0 == strcmp(first_section_name, "_declarations")) {
		if (first->flavor == NODE_DECL && second->flavor == NODE_DECL) {
			if (first->data.d_data->flavor != second->data.d_data->flavor) {
				CHECK_FLAVOR_ORDERING(d_data, DECL_BOOL, ORDER_DECLARATION_SUBSECTION);
				CHECK_FLAVOR_ORDERING(d_data, DECL_ATTRIBUTE, ORDER_DECLARATION_SUBSECTION);
				// Types and roles should intersperse
			} else {
				// TODO: same subsection
			}
		}
		return ORDER_EQUAL;
	}

	// Local policy rules sections
	enum local_subsection lss_first = get_local_subsection(ordering_data->mod_name, first);
	enum local_subsection lss_second = get_local_subsection(ordering_data->mod_name, second);

	if (lss_first == LSS_UNKNOWN || lss_second == LSS_UNKNOWN) {
		return ORDER_EQUAL; // ... Maybe? Should this case be handled earlier?
	}

	CHECK_ORDERING(lss_first, lss_second, LSS_SELF, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_OWN, ORDER_LOCAL_SUBSECTION);

	if (variant == ORDER_REF) {
		CHECK_ORDERING(lss_first, lss_second, LSS_KERNEL_MOD, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_KERNEL, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_SYSTEM, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_OTHER, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_BUILD_OPTION, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_CONDITIONAL, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_TUNABLE, ORDER_LOCAL_SUBSECTION);
		CHECK_ORDERING(lss_first, lss_second, LSS_OPTIONAL, ORDER_LOCAL_SUBSECTION);
	}

	// TODO: alphabetical

	return ORDER_EQUAL;
}

enum order_difference_reason compare_nodes_refpolicy(struct ordering_metadata *ordering_data,
                                                     const struct policy_node *first,
                                                     const struct policy_node *second)
{
	return compare_nodes_refpolicy_generic(ordering_data, first, second, ORDER_REF);
}

enum order_difference_reason compare_nodes_refpolicy_lax(struct ordering_metadata *ordering_data,
                                                         const struct policy_node *first,
                                                         const struct policy_node *second)
{
	return compare_nodes_refpolicy_generic(ordering_data, first, second, ORDER_LAX);
}

const char *lss_to_string(enum local_subsection lss)
{
	switch (lss) {
	case LSS_SELF:
		return "self";
	case LSS_OWN:
		return "own module rules";
	case LSS_KERNEL_MOD:
		return "kernel_mod";
	case LSS_KERNEL:
		return "kernel";
	case LSS_SYSTEM:
		return "system";
	case LSS_OTHER:
		return "general interfaces";
	case LSS_BUILD_OPTION:
		return "build options";
	case LSS_CONDITIONAL:
		return "conditional blocks";
	case LSS_TUNABLE:
		return "tunable policy blocks";
	case LSS_OPTIONAL:
		return "optional policy blocks";
	case LSS_UNKNOWN:
	default:
		return "unknown subsection";
	}
}

char *get_ordering_reason(struct ordering_metadata *order_data, unsigned int index)
{
	unsigned int distance = 1;
	unsigned int nearest_index = 0;
	enum order_difference_reason reason = ORDER_EQUAL;
	while (nearest_index == 0) {
		if (distance < index &&
		    order_data->nodes[index-distance].in_order) {
			reason = compare_nodes_refpolicy(order_data,
							 order_data->nodes[index-distance].node,
							 order_data->nodes[index].node);
			if (reason < 0) {
				nearest_index = index - distance;
				break;
			}
		}
		if (index + distance < order_data->order_node_len &&
		    order_data->nodes[index+distance].in_order) {
			reason = compare_nodes_refpolicy(order_data,
	                                                 order_data->nodes[index].node,
	                                                 order_data->nodes[index+distance].node);
			if (reason < 0) {
				nearest_index = index + distance;
				break;
			}
		}
		distance++;
		if ((distance > index) &&
		    (index + distance > order_data->order_node_len)) {
			return NULL; // Error
		}
	}

	const struct policy_node *this_node = order_data->nodes[index].node;
	const struct policy_node *other_node = order_data->nodes[nearest_index].node;

	const char *before_after = NULL;
	if (nearest_index > index) {
		before_after = "before";
	} else {
		before_after = "after";
	}

	const char *reason_str = NULL;
	char *followup_str = NULL;
	enum local_subsection other_lss;
	const char *node_section = NULL;
	const char *other_section = NULL;

	switch (-reason) {
	case ORDER_EQUAL:
		return NULL; // Error
	case ORDER_SECTION:
		node_section = get_section(this_node);
		other_section = get_section(other_node);
		if (!node_section || !other_section) {
			return NULL; // Error
		}
		if (0 == strcmp("_declarations", node_section)) {
			// This is the first section
			reason_str = "that is not a declaration";
		} else if (0 == strcmp("_declarations", other_section)) {
			// The other section is the first section
			if (other_node->flavor == NODE_IF_CALL && is_transform_if(other_node->data.ic_data->name)) {
				reason_str = "that is a transform interface";
			} else {
				reason_str = "that is a declaration";
			}
		} else {
			reason_str = "that is in a different section";
			int r = asprintf(&followup_str, "  (This node is in the section for %s rules and the other is in the section for %s rules.)", node_section, other_section);
			if (r == -1) {
				return NULL; //ERROR
			}
		}
		break;
	case ORDER_DECLARATION_SUBSECTION:
		reason_str = "that is associated with a different sort of declaration";
		break;
	case ORDER_LAYERS:
		// TODO
		reason_str = "that is in another layer";
		break;
	case ORDER_LOCAL_SUBSECTION:
		other_lss = get_local_subsection(order_data->mod_name, other_node);
		switch (other_lss) {
		case LSS_SELF:
			reason_str = "that is a self rule";
			break;
		case LSS_OWN:
			reason_str = "that refers to types owned by this module";
			break;
		case LSS_KERNEL_MOD:
			reason_str = "that calls an interface located in the kernel module";
			break;
		case LSS_KERNEL:
			reason_str = "that calls an interface located in the kernel layer";
			break;
		case LSS_SYSTEM:
			reason_str = "that calls an interface located in the system layer";
			break;
		case LSS_OTHER:
			reason_str = "that calls an interface not located in the kernel or system layer";
			break;
		case LSS_BUILD_OPTION:
			reason_str = "that is controlled by a build option";
			break;
		case LSS_CONDITIONAL:
			reason_str = "that is in a conditional policy block";
			break;
		case LSS_TUNABLE:
			reason_str = "that is in a tunable block";
			break;
		case LSS_OPTIONAL:
			reason_str = "that is in an optional block";
			break;
		case LSS_UNKNOWN:
			return NULL; //Error
		default:
			//Shouldn't happen
			return NULL;
		}
		if (other_lss == LSS_KERNEL || other_lss == LSS_SYSTEM || other_lss == LSS_OTHER) {
			enum local_subsection this_lss = get_local_subsection(order_data->mod_name, this_node);
			if (this_lss == LSS_KERNEL || this_lss == LSS_SYSTEM) {
				int r = asprintf(&followup_str, "  (This interface is in the %s layer.)", lss_to_string(this_lss));
				if (r == -1) {
					return NULL; //ERROR
				}
			} else if (this_lss == LSS_OTHER) {
				followup_str = strdup("  (This interface is in a layer other than kernel or system)");
			} else if (this_lss == LSS_KERNEL_MOD) {
				followup_str = strdup("  (This interface is in the kernel module.)");
			}
			// Otherwise, it's not an interface call and is hopefully obvious to the user what layer its in
		}
		break;
	case ORDER_ALPHABETICAL:
		if (nearest_index > index) {
			reason_str = "that is alphabetically earlier";
		} else {
			reason_str = "that is alphabetically later";
		}
		break;
	case ORDERING_ERROR:
		return NULL;
	default:
		//Shouldn't happen
		return NULL;
	}
	size_t str_len = strlen(reason_str) +
	                 strlen(before_after) +
	                 strlen("Line out of order.  It is of type ") +
	                 strlen(lss_to_string(get_local_subsection(order_data->mod_name, this_node))) + 1 +
	                 strlen(" line ") +
	                 13; // 13 is enough for the maximum
	                     // length of an unsigned int (10)
	                     // plus a final period, a space
	                     // and a null terminator
	if (followup_str) {
		str_len += strlen(followup_str);
	}

	char *ret = malloc(sizeof(char) * str_len);

	ssize_t written = snprintf(ret, str_len,
	                           "Line out of order.  It is of type %s %s line %u %s.",
	                           lss_to_string(get_local_subsection(order_data->mod_name, this_node)),
	                           before_after,
	                           other_node->lineno,
	                           reason_str);

	if (written < 0) {
		free(followup_str);
		return NULL;
	}

	if (followup_str) {
		strncat(ret, followup_str, str_len - (size_t)written);
	}

	free(followup_str);
	return ret;
}

void free_ordering_metadata(struct ordering_metadata *to_free)
{
	if (to_free == NULL) {
		return;
	}
	free_section_data(to_free->sections);
	free(to_free);
}

void free_section_data(struct section_data *to_free)
{
	if (to_free == NULL) {
		return;
	}
	free(to_free->section_name);
	free_section_data(to_free->next);
	free(to_free);
}
