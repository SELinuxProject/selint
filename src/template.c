#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "template.h"

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
				return NULL;
			}
		}
		strcpy(ret_pos, cur->string);
		ret_pos += strlen(cur->string);
		// There is no way this works...
	}
	return ret;
}
