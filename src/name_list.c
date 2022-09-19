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

#include "name_list.h"

#include <stdlib.h>
#include <string.h>

#include "tree.h"
#include "xalloc.h"

static bool is_compatible(enum name_flavor a, enum name_flavor b)
{
	if (b == NAME_UNKNOWN) {
		return true;
	}

	switch (a) {
	case NAME_TYPE:
		return b == NAME_TYPE || b == NAME_TYPE_OR_ATTRIBUTE;
	case NAME_TYPEATTRIBUTE:
		return b == NAME_TYPEATTRIBUTE || b == NAME_TYPE_OR_ATTRIBUTE;
	case NAME_TYPE_OR_ATTRIBUTE:
		return b == NAME_TYPE || b == NAME_TYPEATTRIBUTE || b == NAME_TYPE_OR_ATTRIBUTE;
	case NAME_ROLE:
		return b == NAME_ROLE || b == NAME_ROLE_OR_ATTRIBUTE;
	case NAME_ROLEATTRIBUTE:
		return b == NAME_ROLEATTRIBUTE || b == NAME_ROLE_OR_ATTRIBUTE;
	case NAME_ROLE_OR_ATTRIBUTE:
		return b == NAME_ROLE || b == NAME_ROLEATTRIBUTE || b == NAME_ROLE_OR_ATTRIBUTE;
	case NAME_CLASS:
		return b == NAME_CLASS;
	case NAME_PERM:
		return b == NAME_PERM;
	case NAME_USER:
		return b == NAME_USER;
	case NAME_BOOL:
		return b == NAME_BOOL;
	case NAME_UNKNOWN:
		return true;
	default:
		// should never happen
		return 0;
	}
}

bool name_is_type(const struct name_data *name)
{
	return is_compatible(name->flavor, NAME_TYPE);
}

bool name_is_typeattr(const struct name_data *name)
{
	return is_compatible(name->flavor, NAME_TYPEATTRIBUTE);
}

bool name_is_role(const struct name_data *name)
{
	return is_compatible(name->flavor, NAME_ROLE);
}

bool name_is_roleattr(const struct name_data *name)
{
	return is_compatible(name->flavor, NAME_ROLEATTRIBUTE);
}

bool name_is_class(const struct name_data *name)
{
	return is_compatible(name->flavor, NAME_CLASS);
}

bool name_list_contains_name(const struct name_list *nl, const struct name_data *name)
{
	for (;nl; nl = nl->next) {
		if (!is_compatible(nl->data->flavor, name->flavor)) {
			continue;
		}

		if (0 == strcmp(nl->data->name, name->name)) {
			return true;
		}
	}
	return false;
}

struct name_list *name_list_from_sl_with_traits(const struct string_list *sl,
                                                enum name_flavor flavor,
                                                const struct string_list *traits)
{
	if (!sl) {
		return NULL;
	}
	struct name_list *ret = xmalloc(sizeof(struct name_list));
	struct name_list *cur = ret;

	while (sl) {
		struct name_data *data = xmalloc(sizeof(struct name_data));
		data->name = xstrdup(sl->string);
		data->flavor = flavor;
		data->traits = copy_string_list(traits);
		cur->data = data;

		if (sl->next) {
			cur->next = xmalloc(sizeof(struct name_list));
		} else {
			cur->next = NULL;
		}
		sl = sl->next;
		cur = cur->next;
	}
	return ret;
}

struct name_list *name_list_create(const char *name, enum name_flavor flavor)
{
	struct name_data *data = xmalloc(sizeof(struct name_data));
	data->name = xstrdup(name);
	data->flavor = flavor;
	data->traits = NULL;
	struct name_list *ret = xmalloc(sizeof(struct name_list));
	ret->data = data;
	ret->next = NULL;

	return ret;
}

struct name_list *name_list_from_decl(const struct declaration_data *decl)
{
	struct name_data *data = xmalloc(sizeof(struct name_data));
	data->name = xstrdup(decl->name);
	data->traits = NULL;

	struct name_list *extra = NULL;

	switch (decl->flavor) {
	case DECL_TYPE:
		data->flavor = NAME_TYPE;
		extra = name_list_from_sl(decl->attrs, NAME_TYPEATTRIBUTE);
		break;
	case DECL_ATTRIBUTE:
		data->flavor = NAME_TYPEATTRIBUTE;
		break;
	case DECL_ATTRIBUTE_ROLE:
		data->flavor = NAME_ROLEATTRIBUTE;
		break;
	case DECL_ROLE:
		data->flavor = NAME_ROLE;
		break;
	case DECL_USER:
		data->flavor = NAME_USER;
		break;
	case DECL_CLASS:
		data->flavor = NAME_CLASS;
		data->traits = copy_string_list(decl->attrs);
		break;
	case DECL_PERM:
		data->flavor = NAME_PERM;
		break;
	case DECL_BOOL:
		data->flavor = NAME_BOOL;
		break;
	default:
		// should never happen
		data->flavor = NAME_UNKNOWN;
		break;
	}

	struct name_list *ret = xmalloc(sizeof(struct name_list));
	ret->data = data;
	ret->next = extra;

	return ret;
}

struct name_list *concat_name_lists(struct name_list *head, struct name_list *tail)
{
	if (!head) {
		return tail;
	}

	if (!tail) {
		return head;
	}

	struct name_list *cur = head;
	while (cur->next) {
		cur = cur->next;
	}
	cur->next = tail;

	return head;
}

void free_name_list(struct name_list *nl)
{
	if (nl == NULL) {
		return;
	}
	struct name_list *cur = nl;

	while (cur) {
		struct name_list *to_free = cur;
		cur = cur->next;
		free(to_free->data->name);
		free_string_list(to_free->data->traits);
		free(to_free->data);
		free(to_free);
	}
}
