/*
* Copyright 2021 The SELint Contributors
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "infer.h"
#include "color.h"
#include "maps.h"
#include "util.h"

/* Uses directly in the testsuite */
enum selint_error infer_interfaces_shallow(const struct policy_node *node);
enum selint_error infer_interfaces_deep(const struct policy_node *node);

static enum param_flavor name_to_param_flavor(enum name_flavor flavor)
{
	switch (flavor) {
	case NAME_TYPE:
		return PARAM_TYPE;
	case NAME_TYPEATTRIBUTE:
		return PARAM_TYPEATTRIBUTE;
	case NAME_TYPE_OR_ATTRIBUTE:
		return PARAM_TYPE_OR_ATTRIBUTE;
	case NAME_ROLE:
		return PARAM_ROLE;
	case NAME_ROLEATTRIBUTE:
		return PARAM_ROLEATTRIBUTE;
	case NAME_ROLE_OR_ATTRIBUTE:
		return PARAM_ROLE_OR_ATTRIBUTE;
	case NAME_CLASS:
		return PARAM_CLASS;
	case NAME_OBJECT_NAME:
		return PARAM_OBJECT_NAME;
	default:
		// should never happen
		return PARAM_UNKNOWN;
	}
}

enum infer_type { IN_SHALLOW, IN_DEEP };

struct infer_data {
	struct interface_trait *if_data;
	enum infer_type mode;
	const struct policy_node *node;
};

static const char *trait_type_to_str(enum trait_type t)
{
	switch (t) {
	case INTERFACE_TRAIT:
		return "interface";
	case TEMPLATE_TRAIT:
		return "template";
	case MACRO_TRAIT:
		return "macro";
	default:
		// should never happen
		return "unknown-trait-type";
	}
}

static void infer_func(const char *name, enum name_flavor flavor, unsigned short id, void *visitor_data)
{
	if (!name) {
		return;
	}

	struct infer_data *data = visitor_data;

	const char *dollar = strchr(name, '$');
	if (!dollar) {
		return;
	}

	if (0 == strcmp(name, "$*") && flavor == NAME_IF_PARAM && id == 1) {
		const struct interface_trait *call_trait = look_up_in_if_traits_map(data->node->data.ic_data->name);
		if (!call_trait) {
			print_if_verbose("No call trait for %s\n", data->node->data.ic_data->name);
		} else {
			for (int i = 0; i < TRAIT_MAX_PARAMETERS; i++) {
				data->if_data->parameters[i] = call_trait->parameters[i];
			}
		}
		return;
	}

	char *param_end;
	errno = 0;
	unsigned long param_no = strtoul(dollar + 1, &param_end, 10);
	if (param_no == 0 || errno != 0) {
		fprintf(stderr, "%sError%s: Failed to parse parameter number from name '%s' in %s %s!\n",
				color_error(), color_reset(),
				name,
				trait_type_to_str(data->if_data->type),
				data->if_data->name);
		return;
	}
	param_no--; // start counting at 0 ($0 is invalid)
	if (param_no > TRAIT_MAX_PARAMETERS) {
		fprintf(stderr, "%sWarning%s: Only up to %u parameters supported, parsed %lu from name '%s' in %s %s!\n",
				color_warning(), color_reset(),
				TRAIT_MAX_PARAMETERS,
				param_no,
				name,
				trait_type_to_str(data->if_data->type),
				data->if_data->name);
		return;
	}

	// skip dash of exclusions
	if (name[0] == '-') {
		name = name + 1;
	}

	if (dollar == name && *param_end == '\0') {
		// name is just a parameter, e.g. '$1'
		if (data->if_data->parameters[param_no] < PARAM_FINAL_INFERRED) {
			if (data->mode == IN_DEEP && flavor == NAME_IF_PARAM) {
				const struct interface_trait *call_trait = look_up_in_if_traits_map(data->node->data.ic_data->name);
				if (!call_trait) {
					print_if_verbose("No call trait for %s\n", data->node->data.ic_data->name);
				} else {
					data->if_data->parameters[param_no] = call_trait->parameters[id-1];
				}
			} else {
				data->if_data->parameters[param_no] = name_to_param_flavor(flavor);
			}
		}
		return;
	}

	if (data->if_data->parameters[param_no] < PARAM_FINAL_INFERRED) {
		data->if_data->parameters[param_no] = PARAM_TEXT;
	}
}

static enum selint_error infer_interface(struct interface_trait *if_trait, const struct policy_node *node, enum infer_type mode)
{
	struct infer_data data = { if_trait, mode, NULL };
	static unsigned short nesting = 1;

	if (nesting > 40) {
		return SELINT_IF_CALL_LOOP;
	}

	for (; node && node->flavor != NODE_INTERFACE_DEF && node->flavor != NODE_TEMP_DEF; node = dfs_next(node)) {
		if (mode == IN_DEEP && node->flavor == NODE_IF_CALL) {
			const char *call_name = node->data.ic_data->name;
			struct interface_trait *call_trait = look_up_in_if_traits_map(call_name);
			if (!call_trait) {
				print_if_verbose("No call trait found for %s\n", call_name);
			} else if (!call_trait->is_inferred && call_trait->type != MACRO_TRAIT) {
				nesting++;
				enum selint_error ret = infer_interface(call_trait, call_trait->node->first_child, mode);
				nesting--;
				if (ret != SELINT_SUCCESS) {
					return ret;
				}
			}
		}

		data.node = node;
		visit_names_in_node(node, infer_func, &data);
	}

	return SELINT_SUCCESS;
}

enum selint_error infer_interfaces_shallow(const struct policy_node *node)
{
	for (const struct policy_node *cur_node = node; cur_node; cur_node = cur_node->next) {
		// skip non ifs
		if (cur_node->flavor != NODE_INTERFACE_DEF && cur_node->flavor != NODE_TEMP_DEF) {
			continue;
		}

		struct interface_trait *if_trait = malloc(sizeof(struct interface_trait));
		if_trait->name = strdup(cur_node->data.str);
		if_trait->type = (cur_node->flavor == NODE_TEMP_DEF) ? TEMPLATE_TRAIT : INTERFACE_TRAIT;
		if_trait->is_inferred = false;
		memset(if_trait->parameters, 0, sizeof if_trait->parameters);
		if_trait->node = cur_node;

		enum selint_error ret = infer_interface(if_trait, cur_node->first_child, IN_SHALLOW);
		if (ret != SELINT_SUCCESS) {
			return ret;
		}

		bool is_inferred = true;
		for (int i = 0; i < TRAIT_MAX_PARAMETERS; ++i) {
			if (if_trait->parameters[i] == PARAM_UNKNOWN) {
                is_inferred = false;
				break;
			}
		}
        if_trait->is_inferred = is_inferred;

		insert_into_if_traits_map(cur_node->data.str, if_trait);
	}

	return SELINT_SUCCESS;
}

enum selint_error infer_interfaces_deep(const struct policy_node *node)
{
	for (const struct policy_node *cur_node = node; cur_node; cur_node = cur_node->next) {
		// skip non ifs
		if (cur_node->flavor != NODE_INTERFACE_DEF && cur_node->flavor != NODE_TEMP_DEF) {
			continue;
		}

		const char *if_name = cur_node->data.str;
		struct interface_trait *if_trait = look_up_in_if_traits_map(if_name);

		if (if_trait->is_inferred) {
			continue;
		}

		enum selint_error ret = infer_interface(if_trait, cur_node->first_child, IN_DEEP);
		if (ret != SELINT_SUCCESS) {
			return ret;
		}
		for (int i = 0; i < TRAIT_MAX_PARAMETERS; ++i) {
			if (if_trait->parameters[i] == PARAM_UNKNOWN) {
				print_if_verbose("Parameter %d of %s %s not inferred\n",
						 i + 1,
						 trait_type_to_str(if_trait->type),
						 if_trait->name);
			}
		}
		if_trait->is_inferred = true;
	}

	return SELINT_SUCCESS;
}

static void add_refpolicy_macro(const char *name, int param_count, const enum param_flavor flavors[])
{
	struct interface_trait *if_trait = malloc(sizeof(struct interface_trait));
	if_trait->name = strdup(name);
	if_trait->type = MACRO_TRAIT;
	if_trait->is_inferred = true;
	if_trait->node = NULL;
	for (int i = 0; i < TRAIT_MAX_PARAMETERS; i++) {
		if (i < param_count) {
			if_trait->parameters[i] = flavors[i];
		} else {
			if_trait->parameters[i] = PARAM_INITIAL;
		}
	}

	insert_into_if_traits_map(name, if_trait);
}

enum selint_error infer_all_interfaces(const struct policy_file_list *files)
{
    // manually insert common refpolicy macros, since macro definitions are not
    // part of the internal policy representation
	add_refpolicy_macro("can_exec",
			    2,
			    (enum param_flavor[2]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE });
	add_refpolicy_macro("filetrans_pattern",
			    5,
			    (enum param_flavor[5]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE, PARAM_CLASS, PARAM_OBJECT_NAME });
	add_refpolicy_macro("filetrans_add_pattern",
			    5,
		     (enum param_flavor[5]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE, PARAM_CLASS, PARAM_OBJECT_NAME });
	add_refpolicy_macro("domtrans_pattern",
			    3,
			    (enum param_flavor[3]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE });
	add_refpolicy_macro("domain_auto_transition_pattern",
			    3,
			    (enum param_flavor[3]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE });
	add_refpolicy_macro("admin_pattern",
			    2,
			    (enum param_flavor[2]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE });
	add_refpolicy_macro("stream_connect_pattern",
			    4,
			    (enum param_flavor[4]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE });
	add_refpolicy_macro("dgram_send_pattern",
			    4,
			    (enum param_flavor[4]){ PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE, PARAM_TYPE_OR_ATTRIBUTE });


	// first infer only simple ifs; do not infer based on other called sub ifs
	print_if_verbose("Start shallow infer step...\n");
	for (const struct policy_file_node *cur_file = files->head; cur_file; cur_file = cur_file->next) {
		enum selint_error ret = infer_interfaces_shallow(cur_file->file->ast);
		if (ret != SELINT_SUCCESS) {
			return ret;
		}
	}

	// on the second run the policy_nodes are linked to the traits, so we can infer deep
	print_if_verbose("Start deep infer step...\n");
	for (const struct policy_file_node *cur_file = files->head; cur_file; cur_file = cur_file->next) {
		enum selint_error ret = infer_interfaces_deep(cur_file->file->ast);
		if (ret != SELINT_SUCCESS) {
			return ret;
		}
	}

	print_if_verbose("Finished infer steps\n");

	return SELINT_SUCCESS;
}

void free_interface_trait(struct interface_trait *to_free)
{
	if (to_free == NULL) {
		return;
	}

	free(to_free->name);
	free(to_free);
}
