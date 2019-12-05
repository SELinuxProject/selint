#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ordering.h"
#include "maps.h"

int is_optional(const struct policy_node *node);
int is_tunable(const struct policy_node *node);
int is_in_ifdef(const struct policy_node *node);

struct ordering_metadata *prepare_ordering_metadata(const struct policy_node *head)
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
			printf("Line: %d, Section %s: LSS: %d\n",
			       nodes[i].node->lineno,
			       get_section(nodes[i].node),
			       get_local_subsection(nodes[i].node));
		}
	}
#endif
}

enum selint_error add_section_info(struct section_data *sections,
                                   char *section_name,
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

char *get_section(const struct policy_node *node)
{
	if (!node) {
		return NULL; //Error
	}

	switch (node->flavor) {
	case NODE_TE_FILE:
	case NODE_IF_FILE:
	case NODE_FC_FILE:
		return NULL; // Should never happen
	case NODE_AV_RULE:
		if (node->data.av_data->flavor == AV_RULE_NEVERALLOW) {
			// These are somewhat of a unique situation, and the style guide
			// doesn't mention them explicitely.  Maybe they should just group
			// like other av rules, but they can often have multiple types.
			// Additionally, the below code assumes that the first string in
			// the sources is a type or attribute, but in the case of neverallows
			// it can be "~"
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
	case NODE_TM_RULE:
	case NODE_TC_RULE:
		// TODO: Are type_member and type_change the same as tt
		// from an ordering standpoint?
		// The case of multiple source types is weird.  For now
		// just using the first one seems fine.
		return node->data.av_data->sources->string;
	case NODE_ROLE_ALLOW:
		// This is not in the style guide. I normally see it grouped
		// with declarations, but maybe a future ordering configuration
		// can sort it that way
		return "_non_ordered";
	case NODE_DECL:
	case NODE_ALIAS:
	case NODE_TYPE_ALIAS:
	case NODE_TYPE_ATTRIBUTE:
		return "_declarations";
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
		if (!is_optional(node) &&
		    (look_up_in_template_map(node->data.ic_data->name) ||
		     is_transform_if(node->data.ic_data->name) ||
		     0 == strcmp(node->data.ic_data->name, "gen_bool") ||
		     0 == strcmp(node->data.ic_data->name, "gen_tunable"))) {
			return "_declarations";
		} else if (is_filetrans_if(node->data.ic_data->name)) {
			return "_non_ordered";
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

float get_avg_line_by_name(char *section_name, struct section_data *sections)
{
	while (0 != strcmp(sections->section_name, section_name)) {
		sections = sections->next;
		if (!sections) {
			return -1; //Error
		}
	}
	return sections->avg_line;
}

int is_self_rule(const struct policy_node *node)
{
	return node->flavor == NODE_AV_RULE &&
	       node->data.av_data &&
	       node->data.av_data->targets &&
	       0 == strcmp(node->data.av_data->targets->string, "self");
}

int is_own_module_rule(const struct policy_node *node)
{
	if (node->flavor != NODE_AV_RULE &&
	    node->flavor != NODE_IF_CALL) {
		return 0;
	}

	char *domain_name = get_section(node);
	if (!domain_name) {
		return 0;
	}
	char *current_mod = look_up_in_decl_map(domain_name, DECL_TYPE);
	if (!current_mod) {
		current_mod = look_up_in_decl_map(domain_name, DECL_ATTRIBUTE);
	}
	if (!current_mod) {
		return 0; // Our section isn't a valid type or attribute
	}
	if (node->flavor == NODE_IF_CALL) {
		// These should actually be patterns, not real calls
		if (look_up_in_ifs_map(node->data.ic_data->name)) {
			return 0;
		}
	}
	struct string_list *types = get_types_in_node(node);
	struct string_list *cur = types;
	while (cur) {
		char *module_of_type_or_attr = look_up_in_decl_map(cur->string, DECL_TYPE);
		if (!module_of_type_or_attr) {
			module_of_type_or_attr = look_up_in_decl_map(cur->string, DECL_ATTRIBUTE);
		}
		if (module_of_type_or_attr &&
		    0 != strcmp(module_of_type_or_attr, current_mod)) {
			free_string_list(types);
			return 0;
		}
		cur = cur->next;
	}
	free_string_list(types);
	// This assumes that not found strings are not types from other modules.
	// This is probably necessary because we'll find strings like "file" or
	// "read_file_perms" for example.  However, in normal mode without context
	// this could definitely be a problem because we won't find types from
	// other modules
	return 1;
}

int check_call_layer(const struct policy_node *node, char *layer_to_check)
{
	if (node->flavor != NODE_IF_CALL) {
		return 0;
	}
	char *mod_name = look_up_in_ifs_map(node->data.ic_data->name);
	if (!mod_name) {
		// not an actual interface
		return 0;
	}
	char *layer_name = look_up_in_mod_layers_map(mod_name);
	if (!layer_name) {
		return 0;
	}
	return (0 == strcmp(layer_name, layer_to_check));
}

int is_kernel_layer_if_call(const struct policy_node *node)
{
	return check_call_layer(node, "kernel");
}

int is_system_layer_if_call(const struct policy_node *node)
{
	return check_call_layer(node, "system");
}

int is_optional(const struct policy_node *node)
{
	while (node) {
		if (node->flavor == NODE_OPTIONAL_POLICY ||
		    node->flavor == NODE_OPTIONAL_ELSE) {
			return 1;
		}
		node = node->parent;
	}
	return 0;
}

int is_tunable(const struct policy_node *node)
{
	while (node) {
		if (node->flavor == NODE_TUNABLE_POLICY) {
			return 1;
		}
		node = node->parent;
	}
	return 0;
}

int is_in_ifdef(const struct policy_node *node)
{
	while (node) {
		if (node->flavor == NODE_IFDEF) {
			return 1;
		}
		node = node->parent;
	}
	return 0;
}

enum local_subsection get_local_subsection(const struct policy_node *node)
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
	} else if (is_own_module_rule(node)) {
		return LSS_OWN;
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

#define CHECK_ORDERING(to_check_first, to_check_second, comp, ret) \
	if (to_check_first == comp) { \
		return ret; \
	} \
	if (to_check_second == comp) { \
		return -ret; \
	} \
// Call this in order of an ordering on enums.  It returns a positve or
// negative value based on which one it encounters first.
#define CHECK_FLAVOR_ORDERING(data_flavor, comp, ret) \
	CHECK_ORDERING(first->data.data_flavor->flavor, second->data.data_flavor->flavor, comp, ret)

enum order_difference_reason compare_nodes_refpolicy(struct ordering_metadata *ordering_data,
                                                     const struct policy_node *first,
                                                     const struct policy_node *second)
{
	char *first_section_name = get_section(first);
	char *second_section_name = get_section(second);

	if (first_section_name == NULL || second_section_name == NULL) {
		return ORDERING_ERROR;
	}

	if (0 == strcmp(first_section_name, "_non_ordered") ||
	    0 == strcmp(second_section_name, "_non_ordered")) {
		return ORDER_EQUAL;
	}

	if (0 != strcmp(first_section_name, second_section_name)) {
		if (0 != strcmp(first_section_name, "_declarations") &&
		    (0 == strcmp(second_section_name, "_declarations") ||
		     (get_avg_line_by_name(first_section_name, ordering_data->sections) >
		      get_avg_line_by_name(second_section_name, ordering_data->sections)))) {
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
	enum local_subsection lss_first = get_local_subsection(first);
	enum local_subsection lss_second = get_local_subsection(second);

	if (lss_first == LSS_UNKNOWN || lss_second == LSS_UNKNOWN) {
		return ORDER_EQUAL; // ... Maybe? Should this case be handled earlier?
	}

	CHECK_ORDERING(lss_first, lss_second, LSS_SELF, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_OWN, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_KERNEL, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_SYSTEM, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_OTHER, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_BUILD_OPTION, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_CONDITIONAL, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_TUNABLE, ORDER_LOCAL_SUBSECTION);
	CHECK_ORDERING(lss_first, lss_second, LSS_OPTIONAL, ORDER_LOCAL_SUBSECTION);

	// TODO: alphabetical

	return ORDER_EQUAL;
}

char *lss_to_string(enum local_subsection lss)
{
	switch (lss) {
	case LSS_SELF:
		return "self";
	case LSS_OWN:
		return "own module rules";
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
	enum order_difference_reason reason;
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

	char *before_after = NULL;
	if (nearest_index > index) {
		before_after = "before";
	} else {
		before_after = "after";
	}

	char *reason_str = NULL;
	char *followup_str = NULL;
	enum local_subsection other_lss;
	char *node_section = NULL;
	char *other_section = NULL;

	switch (-reason) {
	case ORDER_EQUAL:
		return NULL; // Error
	case ORDER_SECTION:
		node_section = get_section(this_node);
		other_section = get_section(other_node);
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
			asprintf(&followup_str, "  (This node is in the section for %s rules and the other is in the section for %s rules.)", node_section, other_section);
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
		other_lss = get_local_subsection(other_node);
		switch (other_lss) {
		case LSS_SELF:
			reason_str = "that is a self rule";
			break;
		case LSS_OWN:
			reason_str = "that refers to types owned by this module";
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
			reason_str = "that is controled by a build option";
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
			enum local_subsection this_lss = get_local_subsection(this_node);
			if (this_lss == LSS_KERNEL || this_lss == LSS_SYSTEM) {
				asprintf(&followup_str, "  (This interface is in the %s layer.)", lss_to_string(this_lss));
			} else if (this_lss == LSS_OTHER) {
				followup_str = strdup("  (This interface is in a layer other than kernel or system)");
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
	                 strlen("Line out of order.  It is ") +
	                 strlen(" line ") +
	                 13; // 13 is enough for the maximum
	                     // length of an unsigned int (10)
	                     // plus a final period, a space
	                     // and a null terminator
	if (followup_str) {
		str_len += strlen(followup_str);
	}

	char *ret = malloc(sizeof(char) * str_len);

	size_t written = snprintf(ret, str_len,
	                          "Line out of order.  It is %s line %u %s.",
	                          before_after,
	                          other_node->lineno,
	                          reason_str);

	if (followup_str) {
		strncat(ret, followup_str, str_len - written);
	}

	free(followup_str);
	return ret;
}

int check_transform_interface_suffix(char *if_name)
{
	char *suffix = strrchr(if_name, '_');
	if (suffix &&
	    (0 == strcmp(suffix, "_type") ||
	     0 == strcmp(suffix, "_file") ||
	     0 == strcmp(suffix, "_domain") ||
	     0 == strcmp(suffix, "_node") ||
	     // Next three are found in mta module
	     0 == strcmp(suffix, "_agent") ||
	     0 == strcmp(suffix, "_delivery") ||
	     0 == strcmp(suffix, "_sender") ||
	     0 == strcmp(suffix, "_boolean") ||
	     0 == strcmp(suffix, "_content") ||
	     0 == strcmp(suffix, "_constrained") ||
	     0 == strcmp(suffix, "_executable") ||
	     0 == strcmp(suffix, "_object") ||
	     0 == strcmp(suffix, "_exemption"))) {
		return 1;
	} else {
		return 0;
	}
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
