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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "check_hooks.h"

#define ALLOC_NODE(nl)  if (ck->nl) { \
		loc = ck->nl; \
		while (loc->next) { loc = loc->next; } \
		loc->next = malloc(sizeof(struct check_node)); \
		if (!loc->next) { return SELINT_OUT_OF_MEM; } \
		loc = loc->next; \
} else { \
		ck->nl = malloc(sizeof(struct check_node)); \
		if (!ck->nl) { return SELINT_OUT_OF_MEM; } \
		loc = ck->nl; \
}

enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck,
                            const char *check_id,
                            struct check_result *(*check_function)(const struct check_data *check_data,
                                                                   const struct policy_node *node))
{

	struct check_node *loc;

	switch (check_flavor) {
	case NODE_TE_FILE:
		ALLOC_NODE(te_file_node_checks);
		break;
	case NODE_AV_RULE:
		ALLOC_NODE(av_rule_node_checks);
		break;

	case NODE_TT_RULE:
		ALLOC_NODE(tt_rule_node_checks);
		break;

	case NODE_DECL:
		ALLOC_NODE(decl_node_checks);
		break;

	case NODE_INTERFACE_DEF:
		ALLOC_NODE(if_def_node_checks);
		break;

	case NODE_TEMP_DEF:
		ALLOC_NODE(temp_def_node_checks);
		break;

	case NODE_IF_CALL:
		ALLOC_NODE(if_call_node_checks);
		break;

	case NODE_REQUIRE:
		ALLOC_NODE(require_node_checks);
		break;

	case NODE_GEN_REQ:
		ALLOC_NODE(gen_req_node_checks);
		break;

	case NODE_FC_ENTRY:
		ALLOC_NODE(fc_entry_node_checks);
		break;

	case NODE_ERROR:
		ALLOC_NODE(error_node_checks);
		break;

	case NODE_CLEANUP:
		ALLOC_NODE(cleanup_checks);
		break;
	default:
		return SELINT_BAD_ARG;
	}

	loc->check_function = check_function;
	loc->check_id = strdup(check_id);
	loc->next = NULL;

	return SELINT_SUCCESS;
}

enum selint_error call_checks(struct checks *ck, struct check_data *data,
                              struct policy_node *node)
{

	switch (node->flavor) {
	case NODE_TE_FILE:
		return call_checks_for_node_type(ck->te_file_node_checks, data, node);
	case NODE_AV_RULE:
		return call_checks_for_node_type(ck->av_rule_node_checks, data, node);
	case NODE_TT_RULE:
		return call_checks_for_node_type(ck->tt_rule_node_checks, data, node);
	case NODE_DECL:
		return call_checks_for_node_type(ck->decl_node_checks, data, node);
	case NODE_INTERFACE_DEF:
		return call_checks_for_node_type(ck->if_def_node_checks, data, node);
	case NODE_TEMP_DEF:
		return call_checks_for_node_type(ck->temp_def_node_checks, data, node);
	case NODE_IF_CALL:
		return call_checks_for_node_type(ck->if_call_node_checks, data, node);
	case NODE_REQUIRE:
		return call_checks_for_node_type(ck->require_node_checks, data, node);
	case NODE_GEN_REQ:
		return call_checks_for_node_type(ck->gen_req_node_checks, data, node);
	case NODE_FC_ENTRY:
		return call_checks_for_node_type(ck->fc_entry_node_checks, data, node);
	case NODE_ERROR:
		return call_checks_for_node_type(ck->error_node_checks, data, node);
	case NODE_CLEANUP:
		return call_checks_for_node_type(ck->cleanup_checks, data, node);
	default:
		return SELINT_SUCCESS;
	}
}

enum selint_error call_checks_for_node_type(struct check_node *ck_list,
                                            struct check_data *data,
                                            struct policy_node *node)
{

	struct check_node *cur = ck_list;

	while (cur) {
		if (node->exceptions && strstr(node->exceptions, cur->check_id)) {
			cur = cur->next;
			continue;
		}
		struct check_result *res = cur->check_function(data, node);
		if (res) {
			res->lineno = node->lineno;
			display_check_result(res, data);
			free_check_result(res);
		}
		cur = cur->next;
	}
	return SELINT_SUCCESS;
}

void display_check_result(struct check_result *res, struct check_data *data)
{

	int padding = 18 - strlen(data->filename);

	if (padding < 0) {
		padding = 0;
	}

	printf("%s:%*u: (%c): %s (%c-%03u)\n",
	       data->filename,
	       padding,
	       res->lineno,
	       res->severity, res->message, res->severity, res->check_id);
}

struct check_result *alloc_internal_error(char *string)
{
	return make_check_result('F', F_ID_INTERNAL, string);
}

int is_valid_check(char *check_str)
{
	if (!check_str) {
		return 0;
	}

	if (check_str[1] != '-') {
		return 0;
	}

	int max_id = 0;

	char severity = check_str[0];

	switch (severity) {
	case 'C':
		max_id = C_END - 1;
		break;
	case 'S':
		max_id = S_END - 1;
		break;
	case 'W':
		max_id = W_END - 1;
		break;
	case 'E':
		max_id = E_END - 1;
		break;
	case 'F':
		max_id = 2;
		break;
	default:
		return 0;
	}

	int check_id = atoi(check_str+2);
	if (check_id > 0 && check_id <= max_id) {
		return 1;
	} else {
		return 0;
	}
}

void free_check_result(struct check_result *res)
{
	free(res->message);
	free(res);
}

__attribute__ ((format(printf, 3, 4)))
struct check_result *make_check_result(char severity, unsigned int check_id,
                                       char *format, ...)
{

	struct check_result *res = malloc(sizeof(struct check_result));

	res->severity = severity;
	res->check_id = check_id;

	va_list args;
	va_start(args, format);

	if (vasprintf(&res->message, format, args) == -1) {
		free(res);
		res = alloc_internal_error(
			"Failed to generate check result message");
	}

	va_end(args);

	return res;
}

void free_checks(struct checks *to_free)
{
	if (to_free->te_file_node_checks) {
		free_check_node(to_free->te_file_node_checks);
	}
	if (to_free->av_rule_node_checks) {
		free_check_node(to_free->av_rule_node_checks);
	}
	if (to_free->tt_rule_node_checks) {
		free_check_node(to_free->tt_rule_node_checks);
	}
	if (to_free->decl_node_checks) {
		free_check_node(to_free->decl_node_checks);
	}
	if (to_free->if_def_node_checks) {
		free_check_node(to_free->if_def_node_checks);
	}
	if (to_free->temp_def_node_checks) {
		free_check_node(to_free->temp_def_node_checks);
	}
	if (to_free->if_call_node_checks) {
		free_check_node(to_free->if_call_node_checks);
	}
	if (to_free->require_node_checks) {
		free_check_node(to_free->require_node_checks);
	}
	if (to_free->gen_req_node_checks) {
		free_check_node(to_free->gen_req_node_checks);
	}
	if (to_free->fc_entry_node_checks) {
		free_check_node(to_free->fc_entry_node_checks);
	}
	if (to_free->error_node_checks) {
		free_check_node(to_free->error_node_checks);
	}
	if (to_free->cleanup_checks) {
		free_check_node(to_free->cleanup_checks);
	}
	free(to_free);
}

void free_check_node(struct check_node *to_free)
{

	if (to_free->next) {
		free_check_node(to_free->next);
	}
	free(to_free->check_id);
	free(to_free);

}
