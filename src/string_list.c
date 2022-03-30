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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "string_list.h"
int str_in_sl(const char *str, const struct string_list *sl)
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

struct string_list *copy_string_list(const struct string_list *sl)
{
	if (!sl) {
		return NULL;
	}
	struct string_list *ret = malloc(sizeof(struct string_list));
	struct string_list *cur = ret;

	while (sl) {
		cur->string = strdup(sl->string);
		cur->has_incorrect_space = sl->has_incorrect_space;
		cur->arg_start = sl->arg_start;

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

struct string_list *sl_from_str(const char *string)
{
	struct string_list *ret = malloc(sizeof(struct string_list));
	ret->string = strdup(string);
	ret->next = NULL;
	ret->has_incorrect_space = 0;
	ret->arg_start = 0;

	return ret;
}

struct string_list *sl_from_strn(const char *string, size_t len)
{
	struct string_list *ret = malloc(sizeof(struct string_list));
	ret->string = strndup(string, len);
	ret->next = NULL;
	ret->has_incorrect_space = 0;
	ret->arg_start = 0;

	return ret;
}

struct string_list *sl_from_str_consume(char *string)
{
	struct string_list *ret = malloc(sizeof(struct string_list));
	ret->string = string;
	ret->next = NULL;
	ret->has_incorrect_space = 0;
	ret->arg_start = 0;

	return ret;
}

struct string_list *sl_from_strs(int count, ...)
{
	struct string_list *ret = NULL;

	va_list args;
	va_start(args, count);
	for (int i = 0; i < count; ++i) {
		ret = concat_string_lists(ret, sl_from_str(va_arg(args, const char *)));
	}
	va_end(args);

	return ret;
}

struct string_list *concat_string_lists(struct string_list *head, struct string_list *tail)
{
	if (!head) {
		return tail;
	}

	if (!tail) {
		return head;
	}

	struct string_list *cur = head;
	while (cur->next) {
		cur = cur->next;
	}
	cur->next = tail;

	return head;
}

enum selint_error append_to_sl(struct string_list *sl, const char *string)
{
	if (!sl) {
		return SELINT_BAD_ARG;
	}

	while (sl->next) {
		sl = sl->next;
	}

	sl->next = sl_from_str(string);

	return SELINT_SUCCESS;
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
