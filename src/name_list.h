/*
* Copyright 2022 The SELint Contributors
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

#ifndef NAME_LIST_H
#define NAME_LIST_H

#include <stdbool.h>

#include "string_list.h"
// avoid circular include with tree.h
struct declaration_data;


enum name_flavor {
	NAME_UNKNOWN,
	NAME_TYPE,
	NAME_TYPEATTRIBUTE,
	NAME_TYPE_OR_ATTRIBUTE,
	NAME_ROLE,
	NAME_ROLEATTRIBUTE,
	NAME_ROLE_OR_ATTRIBUTE,
	NAME_CLASS,
	NAME_PERM,
	NAME_USER,
	NAME_BOOL,
};

struct name_data {
	enum name_flavor flavor;
	char *name;
	// flavor == NAME_CLASS: list of associated permissions
	struct string_list *traits;
};

bool name_is_type(const struct name_data *name);
bool name_is_typeattr(const struct name_data *name);
bool name_is_role(const struct name_data *name);
bool name_is_roleattr(const struct name_data *name);
bool name_is_class(const struct name_data *name);

struct name_list {
	struct name_data *data;
	struct name_list *next;
};

// Create a name list with a single entry
struct name_list *name_list_create(const char *name, enum name_flavor flavor);

// Create a name list with identifiers from a string list and associate all with flavor
struct name_list *name_list_from_sl_with_traits(const struct string_list *sl,
                                                enum name_flavor flavor,
                                                const struct string_list *traits);
static inline struct name_list *name_list_from_sl(const struct string_list *sl,
                                                  enum name_flavor flavor)
{
	return name_list_from_sl_with_traits(sl, flavor, NULL);
}

// Concat two name lists, accepts NULL lists.
// Note: freeing the returned list will free both original name lists
struct name_list *concat_name_lists(struct name_list *head, struct name_list *tail);

// Create a name list with a single entry from a declaration
struct name_list *name_list_from_decl(const struct declaration_data *decl);

bool name_list_contains_name(const struct name_list *nl, const struct name_data *name);

void free_name_list(struct name_list *nl);

#endif
