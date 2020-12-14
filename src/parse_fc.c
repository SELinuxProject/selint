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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>

#include "parse_fc.h"
#include "tree.h"
#include "maps.h"

// "gen_context("
#define GEN_CONTEXT_LEN 12

struct fc_entry *parse_fc_line(char *line, struct conditional_data *conditional)
{
	const char *whitespace = " \t";

	struct fc_entry *out = malloc(sizeof(struct fc_entry));

	memset(out, 0, sizeof(struct fc_entry));

	char *orig_line = strdup(line); // If the object class is omitted, we need to revert

	char *pos = strtok(line, whitespace);

	if (pos == NULL) {
		goto cleanup;
	}

	out->path = strdup(pos);

	pos = strtok(NULL, whitespace);

	if (pos == NULL) {
		goto cleanup;
	}

	if (pos[0] == '-') {
		if (pos[2] != '\0') {
			goto cleanup;
		}
		out->obj = pos[1];
		pos = strtok(NULL, whitespace);
		if (pos == NULL) {
			goto cleanup;
		}
	}
	// pos points to the start of the context, but spaces in the context may have been
	// overwritten by strtok
	strcpy(line, orig_line);

	if (strncmp("gen_context(", pos, GEN_CONTEXT_LEN) == 0) {
		pos += GEN_CONTEXT_LEN; // Next character
		char *context_part = strtok(pos, ",");
		if (context_part == NULL) {
			goto cleanup;
		}

		char *maybe_s = strtok(NULL, ",");
		char *maybe_c = NULL;
		int i = 0;

		if (maybe_s) {
			maybe_c = strtok(NULL, ",");
			while (maybe_s[i] != '\0' && maybe_s[i] != ')') {
				i++;
			}
			if (maybe_s[i] == '\0') {
				if (!maybe_c) {
					// Missing closing paren
					goto cleanup;
				}
			}
			maybe_s[i] = '\0';
			while (maybe_s[0] != '\0'
			       && (maybe_s[0] == ' ' || maybe_s[0] == '\t')) {
				// trim beginning whitespace
				maybe_s++;
			}
		} else {
			// No mls
			while (context_part[i] != '\0' && context_part[i] != ')') {
				i++;
			}
			if (context_part[i] == '\0') {
				// Missing closing paren
				goto cleanup;
			}
			context_part[i] = '\0';
		}

		if (maybe_c) {
			while (maybe_c[i] != '\0' && maybe_c[i] != ')') {
				i++;
			}
			if (maybe_c[i] == '\0') {
				// Missing closing paren
				goto cleanup;
			}
			maybe_c[i] = '\0';
			while (maybe_c[0] != '\0'
			       && (maybe_c[0] == ' ' || maybe_c[0] == '\t')) {
				// trim beginning whitespace
				maybe_c++;
			}
		}

		out->context = parse_context(context_part);
		if (out->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 1;
		if (maybe_c) {
			out->context->range =
				malloc(strlen(maybe_s) + 1 + strlen(maybe_c) + 1);
			strcpy(out->context->range, maybe_s);
			strcat(out->context->range, ":");
			strcat(out->context->range, maybe_c);
		} else if (maybe_s) {
			out->context->range = strdup(maybe_s);
		} else {
			out->context->range = NULL;
		}
	} else if (strcmp("<<none>>\n", pos) == 0
	           || strcmp("<<none>>\r\n", pos) == 0) {
		out->context = NULL;
	} else {
		out->context = parse_context(pos);
		if (out->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 0;

	}

	if(conditional){
		out->conditional = malloc(sizeof(struct conditional_data));
		out->conditional->flavor = conditional->flavor;
		out->conditional->condition = strdup(conditional->condition);
	}

	free(orig_line);
	return out;

cleanup:
	free(orig_line);
	free_fc_entry(out);
	return NULL;
}

struct sel_context *parse_context(char *context_str)
{

	if (strchr(context_str, '(')) {
		return NULL;
	}

	struct sel_context *context = malloc(sizeof(struct sel_context));
	memset(context, 0, sizeof(struct sel_context));
	// User
	char *pos = strtok(context_str, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->user = strdup(pos);

	// Role
	pos = strtok(NULL, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->role = strdup(pos);

	// Type
	pos = strtok(NULL, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->type = strdup(pos);

	pos = strtok(NULL, ":");

	if (pos) {
		context->range = strdup(pos);
		if (strtok(NULL, ":")) {
			goto cleanup;
		}
	}

	return context;

cleanup:
	free_sel_context(context);
	return NULL;
}

bool check_for_fc_macro(const char *line, const struct string_list *custom_fc_macros)
{
	if (!custom_fc_macros) {
		return false;
	}
	size_t line_len = strlen(line);
	for (;custom_fc_macros; custom_fc_macros = custom_fc_macros->next){
		size_t custom_fc_len = strlen(custom_fc_macros->string);
		if (line_len <= custom_fc_len) {
			continue;
		}
		if (line[custom_fc_len] != '(') {
			continue;
		}
		if (0 == strncmp(line, custom_fc_macros->string, custom_fc_len)) {
			return true;
		}
	}
	return false;
}

struct policy_node* parse_fc_file(const char *filename, const struct string_list *custom_fc_macros)
{
	FILE *fd = fopen(filename, "r");

	if (!fd) {
		return NULL;
	}

	struct policy_node *head = malloc(sizeof(struct policy_node));
	memset(head, 0, sizeof(struct policy_node));
	head->flavor = NODE_FC_FILE;

	struct policy_node *cur = head;

	char *line = NULL;
	char *ifdef_condition = NULL;
	char *ifndef_condition = NULL;
	char *token = NULL;
	struct conditional_data *conditional = NULL;

	ssize_t len_read = 0;
	size_t buf_len = 0;
	unsigned int lineno = 0;
	bool is_within_ifdef = false;
	bool is_within_ifndef = false;
	while ((len_read = getline(&line, &buf_len, fd)) != -1) {
		lineno++;
		if (len_read <= 1 || line[0] == '#') {
			continue;
		} else if (!strncmp(line, "ifdef", 5)) {
			is_within_ifdef = true;
			token = strtok(line, "`");
			if (token) {
				token = strtok(NULL, "'");
				ifdef_condition = strdup(token);
			}
			continue;
		} else if (!strncmp(line, "ifndef", 6)) {
			is_within_ifndef = true;
			token = strtok(line, "`");
			if (token) {
				token = strtok(NULL, "'");
				ifndef_condition = strdup(token);
			}
			continue;
		} else if (!strncmp(line, "')", 2)) {
			//TODO
			//The assumption made here is that ifdef/ifndef
			//blocks always end with '), however there are
			//other legal specifications that would be missed
			//by this assumption. For instance, ending an ifdef
			//block with '  )(note space).
			//This needs to be reworked to account for such cases.
			if (is_within_ifdef) {
				is_within_ifdef = false;
				free(ifdef_condition);
				ifdef_condition = NULL;
				free_conditional_data(conditional);
				conditional = NULL;
			} else if (is_within_ifndef) {
				is_within_ifndef = false;
				free(ifndef_condition);
				ifndef_condition = NULL;
				free_conditional_data(conditional);
				conditional = NULL;
			}
			continue;
		} else if (!strncmp(line, "', `", 4) || !strncmp(line, "',`", 3)) { // Skip over m4 constructs
			continue;
		}
		// TODO: Right now whitespace parses as an error
		// We may want to detect it and report a lower severity issue

		if (check_for_fc_macro(line, custom_fc_macros)) {
			continue;
		}

		if (is_within_ifdef) {
			if(!conditional){
				conditional = malloc(sizeof(struct conditional_data));
				conditional->flavor = CONDITION_IFDEF;
				conditional->condition = strdup(ifdef_condition);
			}
		} else if (is_within_ifndef) {
			if(!conditional){
				conditional = malloc(sizeof(struct conditional_data));
				conditional->flavor = CONDITION_IFNDEF;
				conditional->condition = strdup(ifndef_condition);
			}
		}

		struct fc_entry *entry = parse_fc_line(line, conditional);

		enum node_flavor flavor;
		if (entry == NULL) {
			flavor = NODE_ERROR;

		} else {
			flavor = NODE_FC_ENTRY;

			struct fc_entry_map_info *info = look_up_in_fc_entries_map(entry->path);
			if (!info) {
				//generally we would check if the entry exist in the
				//insert_into_fc_entries_map itself but,due to the
				//fact that we are allocating memory for info and we
				//are relying on the fc_entries_map destructor to free
				//memory allocated for info we want to ensure that
				//the entry does not exist already ahead of time else
				//we will end up with memory leak on info.
				info = malloc(sizeof(struct fc_entry_map_info));
				char *copy = strdup(filename);
				char *fc_name = basename(copy);
				info->entry = entry;
				info->lineno = lineno;
				info->file_name = strdup(fc_name);

				insert_into_fc_entries_map(info);
				free(copy);
			}
		}

		union node_data nd;
		nd.fc_data = entry;
		if (insert_policy_node_next(cur, flavor, nd, lineno)
				!= SELINT_SUCCESS) {
			free_policy_node(head);
			fclose(fd);
			return NULL;
		}
		cur = cur->next;
		free(line);
		line = NULL;
		buf_len = 0;
	}
	free(line);            // getline alloc must be freed even if getline failed
	fclose(fd);

	//If for some reason there was an error parsing that file where
	//an ifdef/ifndef block was never closed, those must be freed.
	free(ifdef_condition);
	free(ifndef_condition);
	free_conditional_data(conditional);

	//TODO remove comment, should we be returning NULL in this case above
	//so that the parse_all_fc_files_in_list function returns a parse error?
	//this will likely requires us to free a lot of stuff before attempting to
	//return NULL, so it may not be worth the level of effort. Besides, missing
	//closed ifdef/ifndef parenthesis would have result in a build error to begin
	//with so that is an issue that should be caught prior to even attempting to
	//run selint

	return head;
}
