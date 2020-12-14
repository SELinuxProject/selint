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

#include <stdio.h>

#include "color.h"
#include "fc_checks.h"
#include "maps.h"
#include "tree.h"
#include "util.h"

#define SETUP_FOR_FC_CHECK(node) \
	if (node->flavor != NODE_FC_ENTRY) { \
		return alloc_internal_error("File context type check called on non file context entry"); \
	} \
	const struct fc_entry *entry = node->data.fc_data; \
	if (!entry) { \
		return alloc_internal_error("Policy node data field is NULL"); \
	} \
	if (!entry->context) { \
		return NULL; \
	} \

struct check_result *check_file_context_types_in_mod(const struct check_data
                                                     *data,
                                                     const struct policy_node
                                                     *node)
{

	SETUP_FOR_FC_CHECK(node)

	if (data->config_check_data->skip_checking_generated_fcs) {
		// do not check probably generated base and entire filecontext file
		// do not check probably generated module filecontext files
		static bool notified = false;
		if (0 == strcmp("base.fc", data->filename) ||
		    0 == strcmp("all_mods.fc", data->filename) ||
		    ends_with(data->filename, strlen(data->filename), ".mod.fc", strlen(".mod.fc"))) {
			if (!notified) {
				printf("%sNote%s: Check S-002 is not performed against generated filecontext files (e.g. %s).\n"\
				       "      This can be disabled with the configuration setting \"skip_checking_generated_fcs\".\n",
				    color_note(), color_reset(), data->filename);
				notified = true;
			}
			return NULL;
		}
	}

	const char *type_decl_mod_name = look_up_in_decl_map(entry->context->type,
	                                                     DECL_TYPE);

	if (!type_decl_mod_name) {
		// If the type is not in any module, that's a different error
		// Returning success on an error condition may seem weird, but it is a
		// redundant condition with another check that will catch this if enabled.
		// Enabling this check and disabling the undeclared check is a valid
		// (although strange) configuration which will result in this condition not
		// being logged, but that is what the user has specifically requested in that
		// situation.  The more common case is having both checks on, and there we
		// don't want to double log
		return NULL;
	}

	if (strcmp(data->mod_name, type_decl_mod_name)) {
		return make_check_result('S',
		                         S_ID_FC_TYPE,
		                         "Type %s is declared in module %s, but used in file context here.",
		                         entry->context->type,
		                         type_decl_mod_name);
	}

	return NULL;
}

struct check_result *check_gen_context_no_range(__attribute__((unused)) const struct check_data
                                                *data,
                                                const struct policy_node
                                                *node)
{
	SETUP_FOR_FC_CHECK(node)

	if (entry->context->has_gen_context && !entry->context->range) {
		return make_check_result('S',
		                         S_ID_MISSING_RANGE,
		                         "No mls levels specified in gen_context");
	}
	return NULL;
}

struct check_result *check_file_context_regex(__attribute__((unused)) const struct check_data *data,
                                              const struct policy_node *node)
{

	SETUP_FOR_FC_CHECK(node)

	const char *path = entry->path;
	char cur = *path;
	char prev = '\0';
	int error = 0;

	while (cur != '\0') {
		char next = *(path + 1);

		if (cur == '[' && prev != '\\') {
			// Fast forward through [ ] groups, because regex characters
			// should not be escaped there
			while (cur != '\0' &&
			       (cur != ']' || prev == '\\')) {
				next = *(path + 1);
				prev = cur;
				cur = next;
				path++;
			}
			continue;
		}
		switch (cur) {
		case '.':
			// require that periods are either escaped or are one of ".*", ".+", or ".?"
			// rarely are periods actually used to just mean one of any character
			if (prev != '\\' && next != '*' && next != '+'
			    && next != '?') {
				error = 1;
			}
			break;
		case '+':
		case '*':
			// require that pluses and asterisks are either escaped or look
			// something kindof like ".*", "(...)*", or "[...]*"
			if (prev != '\\' && prev != '.' && prev != ']'
			    && prev != ')') {
				error = 1;
			}
			break;
		default:
			break;
		}

		if (error) {
			return make_check_result('W', W_ID_FC_REGEX,
			                         "File context path contains a potentially unescaped regex character '%c' at position %d: %s",
			                         cur,
			                         (int)(path - entry->path + 1),
			                         entry->path);
		}

		prev = cur;
		cur = next;
		path++;
	}

	return NULL;
}

struct check_result *check_file_context_error_nodes(__attribute__((unused)) const struct check_data
                                                    *data,
                                                    const struct policy_node
                                                    *node)
{

	if (node->flavor != NODE_ERROR) {
		return NULL;
	}

	return make_check_result('E', E_ID_FC_ERROR, "Bad file context format");
}

struct check_result *check_file_context_users(__attribute__((unused)) const struct check_data *data,
                                              const struct policy_node *node)
{

	SETUP_FOR_FC_CHECK(node)

	const char *user_decl_filename = look_up_in_decl_map(entry->context->user,
	                                               DECL_USER);

	if (!user_decl_filename) {
		return make_check_result('E', E_ID_FC_USER,
		                         "Nonexistent user (%s) listed in fc_entry",
		                         entry->context->user);
	}

	return NULL;
}

struct check_result *check_file_context_roles(__attribute__((unused)) const struct check_data *data,
                                              const struct policy_node *node)
{

	SETUP_FOR_FC_CHECK(node)

	const char *role_decl_filename = look_up_in_decl_map(entry->context->role,
	                                               DECL_ROLE);

	if (!role_decl_filename) {
		return make_check_result('E', E_ID_FC_ROLE,
		                         "Nonexistent role (%s) listed in fc_entry",
		                         entry->context->role);
	}

	return NULL;
}

struct check_result *check_file_context_types_exist(__attribute__((unused)) const struct check_data
                                                    *data,
                                                    const struct policy_node
                                                    *node)
{

	SETUP_FOR_FC_CHECK(node)

	const char *type_decl_filename = look_up_in_decl_map(entry->context->type,
	                                               DECL_TYPE);

	if (!type_decl_filename) {
		return make_check_result('E', E_ID_FC_TYPE,
		                         "Nonexistent type (%s) listed in fc_entry",
		                         entry->context->type);
	}

	return NULL;
}

/**********************************
 * Return true if the two fc_entry nodes are the same
 * and false otherwise
 **********************************/
static bool is_same_fc_entry(const struct fc_entry *entry_one,
                             const struct fc_entry *entry_two)
{
	return !strcmp(entry_one->path, entry_two->path)
		&& ((!entry_one->context && !entry_two->context)	//when <<none>>
			|| (entry_one->obj == entry_two->obj
				&& !strcmp(entry_one->path, entry_two->path)
				&& !strcmp(entry_one->context->range,
				           entry_two->context->range)
				&& !strcmp(entry_one->context->role,
				           entry_two->context->role)
				&& !strcmp(entry_one->context->type,
				           entry_two->context->type)
				&& !strcmp(entry_one->context->user,
				           entry_two->context->user)));
}

/**********************************
 * Return true if an entry has multiple specification
 * and false otherwise
 **********************************/
static bool is_multiple_fc_entry_spec(const struct fc_entry *entry_one,
                                      const struct fc_entry *entry_two)
{

	if (!(entry_two->context && entry_one->context)) {
		return false;
	} else {
		return !strcmp(entry_one->path, entry_two->path)
			&& entry_one->obj == entry_two->obj
			&& !strcmp(entry_one->path, entry_two->path)
			&& (strcmp(entry_one->context->range, entry_two->context->range)
				|| strcmp(entry_one->context->role,
				          entry_two->context->role)
				|| strcmp(entry_one->context->type,
				          entry_two->context->type)
				|| strcmp(entry_one->context->user,
				          entry_two->context->user));
	}
}

/**********************************
 * Return true if the two duplicates or multiple
 * specification would cause problems and false otherwise
 **********************************/
static bool is_problematic(const struct fc_entry *entry_one,
                           const struct fc_entry *entry_two)
{

	/*************************************************************************************
	 * The ideal solution here would be to evaluate ifdef/ifndef parameters, but that    *
	 * seems to be a bit more complicated. We are using this function as an alternate    *
	 * solution to help us determine when multiple specifications of an entry would      *
	 * break the build. To start with we make the assumption that ifdef parameters are   *
	 * mutually exclusive, even though in theory they are not, in practice you should    *
	 * never have distro_redhat and distro_gentoo, for instance both defined. contrary   *
	 * to that, ifndef is not mutually exclusive both in theory and practice so that     *
	 * assumption is made here as well. Those are the condition under which this         *
	 * function will return true:                                                        *
	 *                                                                                   *
	 * 1)Two duplicates whereby none of them is within any ifdef/ifndef.                 *
	 *                                                                                   *
	 * 2)Two duplicates whereby one of them is within an ifdef/ifndef and the other      *
	 *   one is not within any.                                                          *
	 *                                                                                   *
	 * 3)Two duplicates whereby both are within the same ifdef/ifndef. The term both     *
	 *   here does not mean to literally be defined under the same conditional           *
	 *   although it would also return true in this case, instead it is referring to     *
	 *   the parameters or conditions being the same. So if you had the same             *
	 *   specification under distro_redhat in two different files, it would treat them   *
	 *   as being under the same conditional and return true.                            *
	 *                                                                                   *
	 * 4)Two duplicates whereby one is within an ifdef, the other within an ifndef       *
	 *   and the conditions differ i.e ifdef(`distro_gentoo',` and                       *
	 *   ifndef(`distro_redhat',`                                                        *
	 *                                                                                   *
	 * 5)Two duplicates whereby both are within ifndef and the conditions differ i.e     *
	 *   ifndef(`distro_gentoo',` and ifndef(`distro_redhat',`                           *
	 *                                                                                   *
	 * For any other conditions, it returns false                                        *
	 *                                                                                   *
	 * For Future improvement we can consider evaluating ifdef/ifndef instead.           *
	 * The conditional_data which is a field from fc_entry contains a boolean field      *
	 * called 'state' specifically to handle that for future improvement. Currently      *
	 * this field is not used it's just a place holder.                                  *
	 ************************************************************************************/

	if (!entry_one->conditional || !entry_two->conditional)
	{
		return true;
	}
	else if (entry_one->conditional && entry_two->conditional)
	{
		if (entry_one->conditional->flavor == entry_two->conditional->flavor
			&& (!strcmp(entry_one->conditional->condition,
				entry_two->conditional->condition)
				|| (entry_one->conditional->flavor == CONDITION_IFNDEF
					&& strcmp(entry_one->conditional->condition,
					          entry_two->conditional->condition)))) {
			return true;
		} else if (entry_one->conditional->flavor
			!= entry_two->conditional->flavor
			&& strcmp(entry_one->conditional->condition,
			          entry_two->conditional->condition)) {
			return true;
		}
	}
	return false;
}

/**********************************
 * Return true if the node we are currently processing
 * is the one that is already registered in the fc_entry_map
 * else false
 **********************************/
static bool is_the_registered_entry(const struct fc_entry_map_info *registered,
                                    unsigned int lineno, char *filename)
{

	return !strcmp(registered->file_name, filename)
			&& registered->lineno == lineno;
}

struct check_result* check_file_contexts_duplicate_entry(const struct check_data *data,
                                                         const struct policy_node *node)
{
	if (node->flavor == NODE_FC_ENTRY) {
		struct fc_entry_map_info *out = look_up_in_fc_entries_map(
				node->data.fc_data->path);
		struct check_result *ret = NULL;

		if(!out){
			return(alloc_internal_error("Error while parsing file context entry"));
		}

		if (!is_the_registered_entry(out, node->lineno, data->filename)) {
			if (is_same_fc_entry(out->entry, node->data.fc_data)
					&& is_problematic(out->entry, node->data.fc_data)) {

				if (!strcmp(out->file_name, data->filename)) {
					ret = make_check_result('E', E_ID_FC_DUPLICATE_ENTRY,
					                        "Duplicate entry at line (%u) and (%u) for entry \"%s\"",
					                        out->lineno, node->lineno,
					                        node->data.fc_data->path);
				} else {
					ret = make_check_result('E', E_ID_FC_DUPLICATE_ENTRY,
					                        "Duplicate entry at line (%u) and line (%u) from (%s) for entry \"%s\"",
					                        node->lineno, out->lineno, out->file_name,
					                        node->data.fc_data->path);
				}
				return ret;
			} else if (is_multiple_fc_entry_spec(out->entry, node->data.fc_data)
					&& is_problematic(out->entry, node->data.fc_data)) {
				if (!strcmp(out->file_name, data->filename)) {
					ret = make_check_result('E', E_ID_FC_DUPLICATE_ENTRY,
					                        "Multiple specification at line (%u) and (%u) for entry \"%s\"",
					                        out->lineno, node->lineno,
					                        node->data.fc_data->path);
				} else {
					ret = make_check_result('E', E_ID_FC_DUPLICATE_ENTRY,
					                        "Multiple Specification at line (%u) and line (%u) from (%s) for entry \"%s\"",
					                        node->lineno, out->lineno, out->file_name,
					                        node->data.fc_data->path);
				}
				return ret;
			}
		}
	}
	return NULL;
}
