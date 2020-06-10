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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#include "selint_error.h"
#include "string_list.h"
#include "tree.h"
#include "maps.h"

enum order_conf {
	ORDER_REF,
	ORDER_LIGHT,
	ORDER_LAX
};

struct config_check_data {
	enum order_conf order_conf;
	enum decl_flavor order_requires[6];
	bool ordering_requires_same_flavor;
	bool skip_checking_generated_fcs;
};

/*******************************************************************
 * Parse the config file and set the function arguments appropriately
 * Return SELINT_SUCCESS or error code
 ********************************************************************/
enum selint_error parse_config(const char *config_filename,
                               int in_source_mode,
                               char *severity,
                               struct string_list **config_disabled_checks,
                               struct string_list **config_enabled_checks,
                               struct string_list **custom_fc_macros,
                               struct config_check_data *config_check_data);

#endif
