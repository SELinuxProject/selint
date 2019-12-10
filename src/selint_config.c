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
#include <confuse.h>
#include <string.h>

#include "util.h"
#include "selint_config.h"

#define READ_STRING_LIST_FROM_CONFIG(slp, config_name) \
	if (slp) { \
		struct string_list *end = NULL; \
		for (unsigned int i = 0; i < cfg_size(cfg, config_name); i++) { \
			struct string_list *cur = calloc(1, sizeof(struct string_list)); \
			cur->string = strdup(cfg_getnstr(cfg, config_name, i)); \
			cur->next = NULL; \
			if (!end) { \
				*slp = end = cur; \
			} else { \
				end->next = cur; \
				end = end->next; \
			} \
		} \
	} \

void insert_config_declarations(cfg_t * cfg, char *config_item,
                                enum decl_flavor flavor)
{
	for (unsigned int i = 0; i < cfg_size(cfg, config_item); i++) {
		insert_into_decl_map(cfg_getnstr(cfg, config_item, i),
		                     "__assumed__", flavor);
	}
}

enum selint_error parse_config(char *config_filename,
                               int in_source_mode,
                               char *severity,
                               struct string_list **config_disabled_checks,
                               struct string_list **config_enabled_checks)
{

	cfg_opt_t opts[] = {
		CFG_STR("severity",           "convention", CFGF_NONE),
		CFG_STR_LIST("disable",       "{}",         CFGF_NONE),
		CFG_STR_LIST("enable_normal", "{}",         CFGF_NONE),
		CFG_STR_LIST("enable_source", "{}",         CFGF_NONE),
		CFG_STR_LIST("assume_users",  "{}",         CFGF_NONE),
		CFG_STR_LIST("assume_roles",  "{}",         CFGF_NONE),
		CFG_END()
	};
	cfg_t *cfg;

	cfg = cfg_init(opts, CFGF_NONE);

	print_if_verbose("Loading configuration from: %s\n", config_filename);
	if (cfg_parse(cfg, config_filename) == CFG_PARSE_ERROR) {
		printf
		        ("Parse error when attempting to parse configuration file.\n");
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}
	// Not specified on command line.  Read from config
	char *config_severity = cfg_getstr(cfg, "severity");

	if (strcmp(config_severity, "convention") == 0) {
		*severity = 'C';
	} else if (strcmp(config_severity, "style") == 0) {
		*severity = 'S';
	} else if (strcmp(config_severity, "warning") == 0) {
		*severity = 'W';
	} else if (strcmp(config_severity, "error") == 0) {
		*severity = 'E';
	} else if (strcmp(config_severity, "fatal") == 0) {
		*severity = 'F';
	} else {
		printf
		        ("Invalid severity level (%s) specified in config.  Options are \"convention\", \"style\", \"warning\", \"error\" and \"fatal\"",
		        config_severity);
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}

	READ_STRING_LIST_FROM_CONFIG(config_disabled_checks, "disable")
	if (in_source_mode) {
		READ_STRING_LIST_FROM_CONFIG(config_enabled_checks,
		                             "enable_source")
	} else {
		READ_STRING_LIST_FROM_CONFIG(config_enabled_checks,
		                             "enable_normal")

	}

	insert_config_declarations(cfg, "assume_users", DECL_USER);
	insert_config_declarations(cfg, "assume_roles", DECL_ROLE);

	cfg_free(cfg);

	return SELINT_SUCCESS;
}
