/*
* Copyright 2020 The SELint Contributors
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

#include "naming.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

static const char *const reason_invalid_char = "contains invalid character";
static const char *const reason_start_underscore = "starts with an underscore";
static const char *const reason_consecutive_underscores = "contains consecutive underscores";
static const char *const reason_end_underscore = "ends with an underscore";
static const char *const reason_type_postfix = "type does not end with type-specific postfix";
static const char *const reason_role_postfix = "role does not end with role-specific postfix";
static const char *const reason_user_postfix = "user does not end with user-specific postfix";
static const char *const reason_if_no_mod_prefix = "interface has no module name prefix";
static const char *const reason_if_no_postfix = "interface has no postfix";
static const char *const reason_if_invalid_postfix = "interface has an invalid postfix";
static const char *const reason_temp_no_mod_prefix = "template has no module name prefix";
static const char *const reason_temp_no_postfix = "template has no postfix";
static const char *const reason_temp_invalid_postfix = "template has an invalid postfix";


static const char *generic_check(const char *name)
{
	const unsigned char *c = (const unsigned char *)name;

	if (*c == '_') {
		return reason_start_underscore;
	}

	unsigned short prev_is_underscore = 0;
	while (*c != '\0') {
		if (!islower(*c) && !isdigit(*c) && *c != '_') {
			return reason_invalid_char;
		}

		if (*c == '_') {
			if (prev_is_underscore) {
				return reason_consecutive_underscores;
			}

			prev_is_underscore = 1;
		} else {
			prev_is_underscore = 0;
		}

		c++;
	}

	if (*(c-1) == '_') {
		return reason_end_underscore;
	}

	return NULL;
}

static const char *type_check(const char *name)
{
	const size_t name_len = strlen(name);
	if (name_len < 2 || name[name_len-2] != '_' || name[name_len-1] != 't') {
		return reason_type_postfix;
	}

	return NULL;
}

static const char *role_check(const char *name)
{
	const size_t name_len = strlen(name);
	if (name_len < 2 || name[name_len-2] != '_' || name[name_len-1] != 'r') {
		return reason_role_postfix;
	}

	return NULL;
}

static const char *user_check(const char *name)
{
	const size_t name_len = strlen(name);
	if (name_len < 2 || name[name_len-2] != '_' || name[name_len-1] != 'u') {
		return reason_user_postfix;
	}

	return NULL;
}

const char *naming_decl_check(const char *name, enum decl_flavor flavor)
{
	// class and permission names are not in the scope of a policy writer
	if (flavor == DECL_CLASS || flavor == DECL_PERM) {
		return NULL;
	}

	const char *res = generic_check(name);
	if (res) {
		return res;
	}

	switch (flavor) {
	case DECL_TYPE:
		res = type_check(name);
		break;
	case DECL_ATTRIBUTE:
		//TODO
		break;
	case DECL_ROLE:
		res = role_check(name);
		break;
	case DECL_ATTRIBUTE_ROLE:
		//TODO
		break;
	case DECL_USER:
		res = user_check(name);
		break;
	case DECL_BOOL:
		//TODO
		break;
	case DECL_CLASS:
	case DECL_PERM:
		break;
	}

	if (res) {
		return res;
	}

	return NULL;
}

static int mod_prefix_check(const char *name, const char *mod_name)
{
	const size_t mod_name_len = strlen(mod_name);

	if (0 == strncmp(name, mod_name, mod_name_len) && name[mod_name_len] == '_') {
		return 0;
	}

	static const char *const exceptions[][2] = {
		{ "fs"      , "filesystem"   },
		{ "corecmd" , "corecommands" },
		{ "seutil"  , "selinuxutil"  },
		{ "libs"    , "libraries"    },
		{ "dev"     , "devices"      },
		{ "term"    , "terminal"     },
		{ "corenet" , "corenetwork"  },
		{ "auth"    , "authlogin"    },
		{ "userdom" , "userdomain"   },
		{ "sysnet"  , "sysnetwork"   },
	};

	const char *prefix = strchr(name, '_');
	if (!prefix) {
		return 1;
	}

	const size_t prefix_len = (size_t)(prefix - name);

	size_t i;
	for (i = 0; i < (sizeof exceptions / sizeof *exceptions); ++i) {
		if (0 == strncmp(name, exceptions[i][0], prefix_len) &&
		    0 == strcmp(mod_name, exceptions[i][1])) {
			return 0;
		}
	}

	return 1;
}

const char *naming_if_check(const char *name, const char *module_name)
{
	const char *res = generic_check(name);
	if (res) {
		return res;
	}

	if (mod_prefix_check(name, module_name)) {
		return reason_if_no_mod_prefix;
	}

	const char *postfix = strrchr(name, '_');
	if (!postfix) {
		return reason_if_no_postfix;
	}

	static const char *const invalid_postfixes[] = {
		"_pattern",
	};
	size_t i;
	for (i = 0; i < (sizeof invalid_postfixes / sizeof *invalid_postfixes); ++i) {
		if (0 == strcmp(postfix, invalid_postfixes[i])) {
			return reason_if_invalid_postfix;
		}
	}

	return NULL;
}

const char *naming_temp_check(const char *name, const char *module_name)
{
	const char *res = generic_check(name);
	if (res) {
		return res;
	}

	if (mod_prefix_check(name, module_name)) {
		return reason_temp_no_mod_prefix;
	}

	const char *postfix = strrchr(name, '_');
	if (!postfix) {
		return reason_temp_no_postfix;
	}

	if (0 != strcmp(postfix, "_template") &&
	    0 != strcmp(postfix, "_admin")) {
		return reason_temp_invalid_postfix;
	}

	return NULL;
}
