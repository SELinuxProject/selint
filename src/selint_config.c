#include <confuse.h>
#include <string.h>

#include "util.h"
#include "selint_config.h"

enum selint_error parse_config(char *config_filename, char *severity) {

	cfg_opt_t opts[] =
	{
		CFG_STR("severity", "convention", CFGF_NONE),
		CFG_END()
	};
	cfg_t *cfg;
	cfg = cfg_init(opts, CFGF_NONE);

	print_if_verbose("Loading configuration from: %s\n", config_filename);
	if (cfg_parse(cfg, config_filename) == CFG_PARSE_ERROR) {
		printf("Parse error when attempting to parse configuration file.\n");
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}

	// Not specified on command line.  Read from config
	char *config_severity = cfg_getstr(cfg, "severity");
	printf("severity: %s\n", config_severity);

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
		printf("Invalid severity level (%s) specified in config.  Options are \"convention\", \"style\", \"warning\", \"error\" and \"fatal\"", config_severity);
		cfg_free(cfg);
		return SELINT_CONFIG_PARSE_ERROR;
	}

	cfg_free(cfg);

	return SELINT_SUCCESS;
}
