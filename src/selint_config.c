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
			struct string_list *cur = sl_from_str(cfg_getnstr(cfg, config_name, i)); \
			if (!end) { \
				*slp = end = cur; \
			} else { \
				end->next = cur; \
				end = end->next; \
			} \
		} \
	} \

static enum selint_error parse_bool(const char *string, bool *value)
{
	if (0 == strcmp("true", string) ||
	    0 == strcmp("True", string) ||
	    0 == strcmp("TRUE", string) ||
	    0 == strcmp("yes", string) ||
	    0 == strcmp("Yes", string) ||
	    0 == strcmp("YES", string)) {
		*value = true;
		return SELINT_SUCCESS;
	}

	if (0 == strcmp("false", string) ||
	    0 == strcmp("False", string) ||
	    0 == strcmp("FALSE", string) ||
	    0 == strcmp("no", string) ||
	    0 == strcmp("No", string) ||
	    0 == strcmp("NO", string)) {
		*value = false;
		return SELINT_SUCCESS;
	}

	return SELINT_CONFIG_PARSE_ERROR;
}

static void insert_config_declarations(cfg_t * cfg, const char *config_item,
                                enum decl_flavor flavor)
{
	for (unsigned int i = 0; i < cfg_size(cfg, config_item); i++) {
		insert_into_decl_map(cfg_getnstr(cfg, config_item, i),
		                     "__assumed__", flavor);
	}
}

enum selint_error parse_config(const char *config_filename,
                               int in_source_mode,
                               char *severity,
                               struct string_list **config_disabled_checks,
                               struct string_list **config_enabled_checks,
                               struct string_list **custom_fc_macros,
                               struct config_check_data *config_check_data)
{

IGNORE_CONST_DISCARD_BEGIN;
	cfg_opt_t opts[] = {
		CFG_STR("severity",                      "convention",    CFGF_NONE),
		CFG_STR_LIST("disable",                  "{}",            CFGF_NONE),
		CFG_STR_LIST("enable_normal",            "{}",            CFGF_NONE),
		CFG_STR_LIST("enable_source",            "{}",            CFGF_NONE),
		CFG_STR_LIST("assume_users",             "{}",            CFGF_NONE),
		CFG_STR_LIST("assume_roles",             "{}",            CFGF_NONE),
		CFG_STR_LIST("custom_fc_macros",         "{}",            CFGF_NONE),
		CFG_STR_LIST("custom_te_simple_macros",  "{}",            CFGF_NONE),
		CFG_STR("ordering_rules",                "refpolicy-lax", CFGF_NONE),
		CFG_STR_LIST("ordering_requires",        "{ bool, class, role, attribute_role, attribute, type }", CFGF_NONE),
		CFG_STR("ordering_requires_same_flavor", "true",          CFGF_NONE),
		CFG_STR("skip_checking_generated_fcs",   "true",          CFGF_NONE),
		CFG_END()
	};
IGNORE_CONST_DISCARD_END;
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
	const char *config_severity = cfg_getstr(cfg, "severity");

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
		        ("Invalid severity level (%s) specified in config.\n"\
			 "Options are \"convention\", \"style\", \"warning\", \"error\" and \"fatal\"\n",
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

	READ_STRING_LIST_FROM_CONFIG(custom_fc_macros, "custom_fc_macros");

	READ_STRING_LIST_FROM_CONFIG(&(config_check_data->custom_te_simple_macros), "custom_te_simple_macros");

	const char *config_ordering_rules = cfg_getstr(cfg, "ordering_rules");

	if (strcmp(config_ordering_rules, "refpolicy") == 0) {
		config_check_data->order_conf = ORDER_REF;
	} else if (strcmp(config_ordering_rules, "refpolicy-light") == 0) {
		config_check_data->order_conf = ORDER_LIGHT;
	} else if (strcmp(config_ordering_rules, "refpolicy-lax") == 0) {
		config_check_data->order_conf = ORDER_LAX;
	} else {
		printf("Invalid ordering rules (%s) specified in config.\n"\
		       "Options are \"refpolicy\", \"refpolicy-light\"\n"\
		       "and \"refpolicy-lax\"\n",
		       config_ordering_rules);
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}

	// ordering_requires
	const unsigned count = cfg_size(cfg, "ordering_requires");
	if (count != 6) {
		printf("Incorrect amount of ordering_requires flavors (%u) specified in config.\n"\
		       "The required amount is 6.\n",
		       count);
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}
	for (unsigned i = 0; i < 6; ++i) {
		const char *cfg_flavor = cfg_getnstr(cfg, "ordering_requires", i);
		enum decl_flavor parsed_flavor;
		if (0 == strcmp("attribute", cfg_flavor)) {
			parsed_flavor = DECL_ATTRIBUTE;
		} else if (0 == strcmp("attribute_role", cfg_flavor)) {
			parsed_flavor = DECL_ATTRIBUTE_ROLE;
		} else if (0 == strcmp("bool", cfg_flavor)) {
			parsed_flavor = DECL_BOOL;
		} else if (0 == strcmp("class", cfg_flavor)) {
			parsed_flavor = DECL_CLASS;
		} else if (0 == strcmp("role", cfg_flavor)) {
			parsed_flavor = DECL_ROLE;
		} else if (0 == strcmp("type", cfg_flavor)) {
			parsed_flavor = DECL_TYPE;
		} else {
			printf("Invalid ordering_requires flavor (%s) specified in config.\n"\
			       "See configuration file for available options\n",
			       cfg_flavor);
			cfg_free(cfg);
			return SELINT_CONFIG_PARSE_ERROR;
		}

		for (unsigned j = 0; j < i; ++j) {
			if (config_check_data->order_requires[j] == parsed_flavor) {
				printf("Duplicate ordering_requires flavor (%s) specified in config.\n",
				       cfg_flavor);
				cfg_free(cfg);
				return SELINT_CONFIG_PARSE_ERROR;
			}
		}

		config_check_data->order_requires[i] = parsed_flavor;
	}

	// ordering_requires_same_flavor
	const char *config_ordering_requires_same_flavor = cfg_getstr(cfg, "ordering_requires_same_flavor");
	bool ordering_requires_same_flavor;

	enum selint_error r = parse_bool(config_ordering_requires_same_flavor, &ordering_requires_same_flavor);
	if (r != SELINT_SUCCESS) {
		printf("Invalid ordering_requires_same_flavor setting (%s) specified in config.\n"\
		       "Options are \"true\" and \"false\"\n",
		       config_ordering_requires_same_flavor);
		cfg_free(cfg);
		return r;
	}

	config_check_data->ordering_requires_same_flavor = ordering_requires_same_flavor;

	// skip_checking_generated_fcs
	const char *config_skip_checking_generated_fcs = cfg_getstr(cfg, "skip_checking_generated_fcs");
	bool skip_checking_generated_fcs;

	r = parse_bool(config_skip_checking_generated_fcs, &skip_checking_generated_fcs);
	if (r != SELINT_SUCCESS) {
		printf("Invalid skip_checking_generated_fcs setting (%s) specified in config.\n"\
		       "Options are \"true\" and \"false\"\n",
		       config_skip_checking_generated_fcs);
		cfg_free(cfg);
		return r;
	}

	config_check_data->skip_checking_generated_fcs = skip_checking_generated_fcs;

	cfg_free(cfg);

	return SELINT_SUCCESS;
}

void free_selint_config(struct config_check_data *config_check_data)
{
	if (!config_check_data) {
		return;
	}

	free_string_list(config_check_data->custom_te_simple_macros);
}
