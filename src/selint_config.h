#ifndef CONFIG_H
#define CONFIG_H

#include "selint_error.h"
#include "string_list.h"
#include "tree.h"
#include "maps.h"

/*******************************************************************
 * Parse the config file and set the function arguments appropriately
 * Return SELINT_SUCCESS or error code
 ********************************************************************/
enum selint_error parse_config(char *config_filename,
			       int in_source_mode,
			       char *severity,
			       struct string_list **config_disabled_checks,
			       struct string_list **config_enabled_checks);

#endif
