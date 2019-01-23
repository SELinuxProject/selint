#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "template.h"
#include "maps.h"

char *replace_m4(char *orig, struct string_list *args) {
	size_t len_to_malloc = strlen(orig) + 1;
	struct string_list *cur = args;
	while (cur) {
		len_to_malloc += strlen(cur->string);
		cur = cur->next;
	}
	// len_to_malloc is now overestimated, because the length of the original
	// arguments wasn't subtracted and not all args are necessarily substituted
	char *ret = malloc(len_to_malloc);
	char* orig_pos = orig;
	char* ret_pos = ret;
	while (*orig_pos) {
		int arg_num;
		int after_num_pos;

		char *dollar_pos = strchr(orig_pos, '$');
		if (!dollar_pos) {
			strcpy(ret_pos, orig_pos);
			break;
		}
		strncpy(ret_pos, orig_pos, dollar_pos-orig_pos);
		ret_pos += dollar_pos-orig_pos;
		orig_pos = dollar_pos;

		int ret_count = sscanf(orig_pos, "$%d%n", &arg_num, &after_num_pos);
		if ( ret_count != 1 ) { // %n doesn't count for return of sscanf
			free(ret);
			return NULL;
		}
		orig_pos += after_num_pos;
		cur = args;
		while (arg_num > 1 ) {
			cur = cur->next;
			arg_num--;
			if (!cur) {
				free(ret);
				return NULL;
			}
		}
		strcpy(ret_pos, cur->string);
		ret_pos += strlen(cur->string);
	}
	return ret;
}

struct string_list *replace_m4_list(struct string_list *replace_with, struct string_list *replace_from) {
	struct string_list *ret = malloc(sizeof(struct string_list));
	struct string_list *cur = ret;

	cur->string = replace_m4(replace_from->string, replace_with);
	replace_from = replace_from->next;

	while (replace_from) {
		cur->next = malloc(sizeof(struct string_list));
		cur = cur->next;
		cur->string = replace_m4(replace_from->string, replace_with);
		cur->next = NULL;
		replace_from = replace_from->next;
	}
	return ret;
}

enum selint_error add_template_declarations(char *template_name, struct string_list *args, struct string_list *parent_temp_names, char *mod_name) {
	struct string_list *cur = parent_temp_names;
	while (cur) {
		if (strcmp(cur->string, template_name) == 0 ){
			// Loop
			free_string_list(parent_temp_names);
			return SELINT_IF_CALL_LOOP;
		}
			cur = cur->next;
	}

	cur = malloc(sizeof(struct string_list));
	cur->string = strdup(template_name);
	cur->next = parent_temp_names;

	struct if_call_list *calls = look_up_call_in_template_map(template_name);

	while (calls) {
		struct string_list *new_args = replace_m4_list(args, calls->call->args);

		enum selint_error res = add_template_declarations(calls->call->name, new_args, cur, mod_name);
		if (res != SELINT_SUCCESS) {
			return res;
		}

		free_string_list(new_args);
		calls = calls->next;
	}

	struct decl_list *decls = look_up_decl_in_template_map(template_name);

	while (decls) {
		char *new_decl = replace_m4(decls->decl->name, args);
		if (!new_decl) {
			free(cur->string);
			free(cur);
			return SELINT_M4_SUB_FAILURE;
		}
		insert_into_decl_map(new_decl, mod_name, decls->decl->flavor);
		free(new_decl);
		decls = decls->next;
	}
	free(cur->string);
	free(cur);
	return SELINT_SUCCESS;
}
