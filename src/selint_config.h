#ifndef CONFIG_H
#define CONFIG_H

#include "selint_error.h"

/*******************************************************************
 * Parse the config file and set the function arguments appropriately
 * Return SELINT_SUCCESS or error code
 ********************************************************************/
enum selint_error parse_config(char *config_filename, char *severity);

#endif
