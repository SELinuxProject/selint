/*
* Copyright 2021 The SELint Contributors
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

#ifndef INFER_H
#define INFER_H

#include <stdbool.h>

#include "file_list.h"

enum param_flavor {
	/* the first flavors are not final, e.g. they can be replaced by a final one */
	PARAM_INITIAL = 0,
	PARAM_UNKNOWN,
	PARAM_TEXT,
	PARAM_TYPE_OR_ATTRIBUTE,
	PARAM_ROLE_OR_ATTRIBUTE,

	/* the following flavors are final */
	PARAM_FINAL_INFERRED,
	PARAM_TYPE = PARAM_FINAL_INFERRED,
	PARAM_TYPEATTRIBUTE,
	PARAM_ROLE,
	PARAM_ROLEATTRIBUTE,
	PARAM_CLASS,
	PARAM_OBJECT_NAME,
};

enum trait_type {
	INTERFACE_TRAIT,
	TEMPLATE_TRAIT,
	MACRO_TRAIT,
};

#define TRAIT_MAX_PARAMETERS 10 // support max 10 parameters for now
struct interface_trait {
	char *name;
	enum trait_type type;
	bool is_inferred;
	//bool is_transform_if;
	//bool is_filetrans_if;
	//bool is_role_if;
	enum param_flavor parameters[TRAIT_MAX_PARAMETERS];
	const struct policy_node *node;
};

enum selint_error infer_all_interfaces(const struct policy_file_list *files);

void free_interface_trait(struct interface_trait *to_free);

#endif /* INFER_H */
