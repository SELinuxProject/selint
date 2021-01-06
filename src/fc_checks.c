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

struct check_result *check_wide_dir_path_fcontext(__attribute__((unused)) const struct check_data
                                                  *data,
                                                  const struct policy_node
                                                  *node)
{
	SETUP_FOR_FC_CHECK(node)

	if (ends_with(entry->path, strlen(entry->path), "(/.*)?", strlen("(/.*)?"))) {
		return make_check_result('C',
					 C_ID_WIDE_DIR_FC,
					 "File context path %s ends on '(/.*)?', which might match unwanted non-directory entries.",
					 entry->path);
	}

	return NULL;
}

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
