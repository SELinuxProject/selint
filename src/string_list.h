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

#ifndef STRING_LIST_H
#define STRING_LIST_H

#include <stddef.h>
#include <stdint.h>
#include "selint_error.h"

struct string_list {
	char *string;
	struct string_list *next;
	uint8_t has_incorrect_space;
	uint8_t arg_start;
};

int str_in_sl(const char *str, const struct string_list *sl);

// Return an identical copy of sl
struct string_list *copy_string_list(const struct string_list *sl);

// Return a string list with a copy of the given string as single item
struct string_list *sl_from_str(const char *string);
struct string_list *sl_from_strn(const char *string, size_t len);

// Return a string list with the given string as single item
// Takes ownership of the given string
struct string_list *sl_from_str_consume(char *string);

// Return a string list with copies of the given strings
struct string_list *sl_from_strs(int count, ...);

// Concat two string lists, accepts NULL lists.
// Note: freeing the returned list will free both original string lists
struct string_list *concat_string_lists(struct string_list *head, struct string_list *tail);

// Append a copy of a string on the end of the given string list
// Note: this traverses the string list.  In performance critical
// situations with multiple appends, you should save a pointer to the end of the list
enum selint_error append_to_sl(struct string_list *sl, const char *string);

void free_string_list(struct string_list *list);

#endif
