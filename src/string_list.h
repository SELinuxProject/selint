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

struct string_list {
	char *string;
	struct string_list *next;
	int has_incorrect_space;
};

int str_in_sl(const char *str, const struct string_list *sl);

// Return an identical copy of sl
struct string_list *copy_string_list(const struct string_list *sl);

void free_string_list(struct string_list *list);

#endif
