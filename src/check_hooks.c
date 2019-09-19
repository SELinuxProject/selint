#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "check_hooks.h"

#define ALLOC_NODE(nl)	if (ck->nl) {\
				loc = ck->nl;\
				while (loc->next) { loc = loc->next; }\
				loc->next = malloc(sizeof(struct check_node));\
				if (!loc->next) { return SELINT_OUT_OF_MEM; }\
				loc = loc->next;\
			} else {\
				ck->nl = malloc(sizeof(struct check_node));\
				if (!ck->nl) { return SELINT_OUT_OF_MEM; }\
				loc = ck->nl;\
			}


enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck, struct check_result * (*check_function)(const struct check_data *check_data, const struct policy_node *node)) {

	struct check_node *loc;

	switch (check_flavor) {
		case NODE_AV_RULE:
			ALLOC_NODE(av_rule_node_checks);
			break;

		case NODE_TT_RULE:
			ALLOC_NODE(tt_rule_node_checks);
			break;

		case NODE_DECL:
			ALLOC_NODE(decl_node_checks);
			break;

		case NODE_IF_DEF:
			ALLOC_NODE(if_def_node_checks);
			break;

		case NODE_TEMP_DEF:
			ALLOC_NODE(temp_def_node_checks);
			break;

		case NODE_IF_CALL:
			ALLOC_NODE(if_call_node_checks);
			break;

		case NODE_FC_ENTRY:
			ALLOC_NODE(fc_entry_node_checks);
			break;

		case NODE_ERROR:
			ALLOC_NODE(error_node_checks);
			break;

		default:
			return SELINT_BAD_ARG;
	}

	loc->check_function = check_function;
	loc->next = NULL;

	return SELINT_SUCCESS;
}

enum selint_error call_checks(struct checks *ck, struct check_data *data, struct policy_node *node) {

	switch (node->flavor) {
		case NODE_AV_RULE:
			return call_checks_for_node_type(ck->av_rule_node_checks, data, node);
		case NODE_TT_RULE:
			return call_checks_for_node_type(ck->tt_rule_node_checks, data, node);
		case NODE_DECL:
			return call_checks_for_node_type(ck->decl_node_checks, data, node);
		case NODE_IF_DEF:
			return call_checks_for_node_type(ck->if_def_node_checks, data, node);
		case NODE_TEMP_DEF:
			return call_checks_for_node_type(ck->temp_def_node_checks, data, node);
		case NODE_IF_CALL:
			return call_checks_for_node_type(ck->if_call_node_checks, data, node);
		case NODE_FC_ENTRY:
			return call_checks_for_node_type(ck->fc_entry_node_checks, data, node);
		case NODE_ERROR:
			return call_checks_for_node_type(ck->error_node_checks, data, node);
		default:
			return SELINT_SUCCESS;
	}
}

enum selint_error call_checks_for_node_type(struct check_node *ck_list, struct check_data *data, struct policy_node *node) {

	struct check_node *cur = ck_list;

	while (cur) {
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

void display_check_result(struct check_result *res, struct check_data *data) {

	int padding = 18 - strlen(data->filename);
	if (padding < 0) { padding = 0; }

	printf("%s:%*u: (%c): %s (%c-%03u)\n", data->filename, padding, res->lineno, res->severity, res->message, res->severity, res->check_id);
}

struct check_result * alloc_internal_error(char *string) {
	return make_check_result('F', F_ID_INTERNAL, string);
}

void free_check_result(struct check_result *res) {
	free(res->message);
	free(res);
}

__attribute__ ((format (printf, 3, 4))) struct check_result *make_check_result(char severity, unsigned int check_id, char *format, ...) {

	struct check_result *res = malloc(sizeof(struct check_result));
	res->severity = severity;
	res->check_id = check_id;

	va_list args;
	va_start(args, format);

	if (vasprintf(&res->message, format, args) == -1) {
		free(res);
		res = alloc_internal_error("Failed to generate check result message");
	}

	va_end(args);

	return res;
}

void free_checks(struct checks *to_free) {

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
	if (to_free->fc_entry_node_checks) {
		free_check_node(to_free->fc_entry_node_checks);
	}
	if (to_free->error_node_checks) {
		free_check_node(to_free->error_node_checks);
	}
	free(to_free);
}

void free_check_node(struct check_node *to_free) {

	if (to_free->next) {
		free_check_node(to_free->next);
	}
	free(to_free);

}

