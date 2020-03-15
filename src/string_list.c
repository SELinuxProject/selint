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

#include <stdlib.h>
#include <string.h>

#include "string_list.h"
int str_in_sl(const char *str, struct string_list *sl)
{

	if (!sl) {
		return 0;
	}

	while (sl) {
		if (0 == strcmp(sl->string, str)) {
			return 1;
		}
		sl = sl->next;
	}
	return 0;
}

struct string_list *copy_string_list(struct string_list *sl)
{
	if (!sl) {
		return NULL;
	}
	struct string_list *ret = malloc(sizeof(struct string_list));
	struct string_list *cur = ret;

	while (sl) {
		cur->string = strdup(sl->string);
		cur->has_incorrect_space = sl->has_incorrect_space;

		if (sl->next) {
			cur->next = malloc(sizeof(struct string_list));
		} else {
			cur->next = NULL;
		}
		sl = sl->next;
		cur = cur->next;
	}
	return ret;
}

char *join_string_list(const struct string_list *sl)
{
	if (!sl) {
		return strdup("");
	}
	
	size_t len = 0;
	
	const struct string_list *cur = sl;
	while (cur) {
		len += strlen(cur->string);
		len++; // space
		
		cur = cur->next;
	}
	
	char *ret = malloc(len + 1);
	ret[0] = '\0';
	cur = sl;
	while (cur) {
		strcat(ret, cur->string);
		strcat(ret, " ");
		
		cur = cur->next;
	}
	
	ret[len-1] = '\0'; // override last space
	
	return ret;
}	

void free_string_list(struct string_list *list)
{
	if (list == NULL) {
		return;
	}
	struct string_list *cur = list;

	while (cur) {
		struct string_list *to_free = cur;
		cur = cur->next;
		free(to_free->string);
		free(to_free);
	}
}
