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

#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <unistd.h>
#include <sysexits.h>

#include "runner.h"
#include "parse.h"
#include "config.h"
#include "file_list.h"
#include "util.h"
#include "selint_config.h"
#include "startup.h"

int yydebug = 0;

extern int yylex_destroy(void);

extern int verbose_flag;

static void usage(void)
{

	/* *INDENT-OFF* */
	printf("Usage: selint [OPTIONS] FILE [...]\n"\
		"Perform static code analysis on SELinux policy source.\n\n");
	printf("  -c CONFIGFILE, --config=CONFIGFILE\tOverride default config with config\n"\
		"\t\t\t\t\tspecified on command line.  See\n"\
		"\t\t\t\t\tCONFIGURATION section for config file syntax.\n"\
		"  -d CHECKID, --disable=CHECKID\t\tDisable check with the given ID.\n"\
		"  -e CHECKID, --enable=CHECKID\t\tEnable check with the given ID.\n"\
		"  -E, --only-enabled\t\t\tOnly run checks that are explicitly enabled with\n"\
		"\t\t\t\t\tthe --enable option.\n"\
		"  -h, --help\t\t\t\tDisplay this menu\n"\
		"  -l LEVEL, --level=LEVEL\t\tOnly list errors with a severity level at or\n"\
		"\t\t\t\t\tgreater than LEVEL.  Options are C (convention), S (style),\n"\
		"\t\t\t\t\tW (warning), E (error), F (fatal error).\n"\
		"  -s, --source\t\t\t\tRun in \"source mode\" to scan a policy source repository\n"\
		"\t\t\t\t\tthat is designed to compile into a full system policy.\n"\
		"  -r, --recursive\t\t\tScan recursively and check all SELinux policy files found.\n"\
		"  -v, --verbose\t\t\t\tEnable verbose output\n"\
		"  -V, --version\t\t\t\tShow version information and exit.\n"
);
	/* *INDENT-ON* */

}

#define WARN_ON_INVALID_CHECK_ID(id, desc)\
	if (!is_valid_check(id)) {\
		printf("Warning: %s, %s, is not a valid check id.\n", id, desc);\
	}

int main(int argc, char **argv)
{

	char severity = '\0';
	const char *config_filename = NULL;
	int source_flag = 0;
	int recursive_scan = 0;
	int only_enabled = 0;
	int exit_code = EX_OK;

	struct string_list *config_disabled_checks = NULL;
	struct string_list *config_enabled_checks = NULL;
	struct string_list *cl_disabled_checks = NULL;
	struct string_list *cl_enabled_checks = NULL;

	struct string_list *cl_e_cursor = NULL;
	struct string_list *cl_d_cursor = NULL;

	while (1) {

		static struct option long_options[] = {
			{ "config",       required_argument, NULL,          'c' },
			{ "disable",      required_argument, NULL,          'd' },
			{ "enable",       required_argument, NULL,          'e' },
			{ "only-enabled", no_argument,       NULL,          'E' },
			{ "help",         no_argument,       NULL,          'h' },
			{ "level",        required_argument, NULL,          'l' },
			{ "modules-conf", required_argument, NULL,          'm' },
			{ "recursive",    no_argument,       NULL,          'r' },
			{ "source",       no_argument,       NULL,          's' },
			{ "version",      no_argument,       NULL,          'V' },
			{ "verbose",      no_argument,       &verbose_flag, 1   },
			{ 0,              0,                 0,             0   }
		};

		int option_index = 0;

		int c = getopt_long(argc,
		                    argv,
		                    "c:d:e:Ehl:mrsVv",
		                    long_options,
		                    &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {

		//getopt returns 0 when a long option with no short equivalent is used
		case 0:
			break;

		case 'c':
			// Specify config file
			config_filename = optarg;
			break;

		case 'd':
			// Disable a given check
			WARN_ON_INVALID_CHECK_ID(optarg, "disabled on command line");
			if (cl_d_cursor) {
				cl_d_cursor->next =
					calloc(1, sizeof(struct string_list));
				cl_d_cursor = cl_d_cursor->next;
			} else {
				cl_d_cursor =
					calloc(1, sizeof(struct string_list));
				cl_disabled_checks = cl_d_cursor;
			}
			cl_d_cursor->string = strdup(optarg);
			break;

		case 'e':
			// Enable a given check
			WARN_ON_INVALID_CHECK_ID(optarg, "enabled on command line");
			if (cl_e_cursor) {
				cl_e_cursor->next =
					calloc(1, sizeof(struct string_list));
				cl_e_cursor = cl_e_cursor->next;
			} else {
				cl_e_cursor =
					calloc(1, sizeof(struct string_list));
				cl_enabled_checks = cl_e_cursor;
			}
			cl_e_cursor->string = strdup(optarg);
			break;

		case 'E':
			// Only run checks enabled by the --enable flag.
			only_enabled = 1;
			break;

		case 'h':
			// Display usage info and exit
			usage();
			exit(0);

		case 'l':
			// Set the severity level
			severity = optarg[0];
			break;

		case 'm':
			// Specify a modules.conf file.  (Not in the README)
			// TODO
			break;

		case 'r':
			// Scan recursively for files to parse
			recursive_scan = 1;
			break;

		case 's':
			// Run in source mode
			source_flag = 1;
			break;

		case 'V':
			// Output version info and exit
			printf("SELint %s\n", VERSION);
			exit(0);

		case 'v':
			// Run in verbose mode
			verbose_flag = 1;
			break;

		case '?':
			usage();
			exit(EX_USAGE);
		}

	}

	print_if_verbose("Verbose mode enabled\n");

	if (source_flag) {
		print_if_verbose("Source mode enabled\n");
	}

	if (!config_filename) {
		config_filename = SYSCONFDIR "/selint.conf";    // Default install path
		if (0 != access(config_filename, R_OK)) {
			//No default config found
			print_if_verbose(
				"No config specified and could not find default config.");
			config_filename = NULL;
		}
	}

	if (config_filename) {
		char cfg_severity;
		if (SELINT_SUCCESS != parse_config(config_filename, source_flag,
		                                   &cfg_severity, &config_disabled_checks,
		                                   &config_enabled_checks)) {
			// Error message printed by parse_config()
			exit(EX_CONFIG);
		}
		if (severity == '\0') {
			severity = cfg_severity;
		}
	}

	struct string_list *config_check_id = config_disabled_checks;
	while (config_check_id) {
		WARN_ON_INVALID_CHECK_ID(config_check_id->string, "disabled in config");
		config_check_id = config_check_id->next;
	}
	config_check_id = config_enabled_checks;
	while (config_check_id) {
		WARN_ON_INVALID_CHECK_ID(config_check_id->string, "enabled in config");
		config_check_id = config_check_id->next;
	}

	if (severity == '\0') {
		severity = 'C';
	}

	print_if_verbose("Severity level set to %c\n", severity);

	if (optind == argc) {
		usage();
		exit(EX_USAGE);
	}

	struct policy_file_list *te_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *if_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *fc_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *context_files =
		calloc(1, sizeof(struct policy_file_list));

	char **paths = malloc(sizeof(char *) * argc - optind + 1);

	int i = 0;
	while (optind < argc) {
		paths[i++] = argv[optind++];
	}

	paths[i] = NULL;

	FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);

	FTSENT *file = fts_read(ftsp);

	char *modules_conf_path = NULL;

	while (file) {

		char *suffix = file->fts_path + file->fts_pathlen - 3;

		if (!strcmp(suffix, ".te")) {
			file_list_push_back(te_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
		} else if (!strcmp(suffix, ".if")) {
			file_list_push_back(if_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
			char *mod_name = strdup(file->fts_name);
			mod_name[file->fts_namelen - 3] = '\0';
			insert_into_mod_layers_map(mod_name, file->fts_parent->fts_name);
			free(mod_name);
		} else if (!strcmp(suffix, ".fc")) {
			file_list_push_back(fc_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
		} else if (source_flag
		           && !strcmp(file->fts_name, "modules.conf")) {
			// TODO: Make modules.conf name configurable
			modules_conf_path = strdup(file->fts_path);
		} else {
			print_if_verbose(
				"Skipping %s which is not a policy file\n",
				file->fts_path);
			if (!recursive_scan) {
				fts_set(ftsp, file, FTS_SKIP);
			}
		}

		file = fts_read(ftsp);
	}

	fts_close(ftsp);

	free(paths);

	struct checks *ck = register_checks(severity,
	                                    config_enabled_checks,
	                                    config_disabled_checks,
	                                    cl_enabled_checks,
	                                    cl_disabled_checks,
	                                    only_enabled);

	if (!ck) {
		printf("Failed to register checks (bad configuration)\n");
		free_file_list(te_files);
		free_file_list(if_files);
		free_file_list(fc_files);
		free_file_list(context_files);
		free(modules_conf_path);
		return EX_CONFIG;
	}
	// Load object classes and permissions
	if (source_flag) {
		load_access_vectors_source();
		if (modules_conf_path) {
			enum selint_error res =
				load_modules_source(modules_conf_path);
			if (res != SELINT_SUCCESS) {
				printf("Error loading modules.conf: %d\n", res);
			} else {
				print_if_verbose("Loaded modules from %s\n",
				                 modules_conf_path);
			}
		} else {
			printf("Failed to locate modules.conf file.\n");
		}
	} else {
		load_access_vectors_normal("/sys/fs/selinux/class");    // TODO
		load_modules_normal();
		enum selint_error res = load_devel_headers(context_files);
		if (res != SELINT_SUCCESS) {
			printf("Error loading SELinux development header files.\n");
		}
	}

	free(modules_conf_path);

	enum selint_error res = run_analysis(ck, te_files, if_files, fc_files, context_files);
	switch (res) {
	case SELINT_SUCCESS:
		break;
	case SELINT_PARSE_ERROR:
		printf("Error during parsing\n");
		exit_code = EX_SOFTWARE;
		break;
	default:
		printf("Internal error: %d\n", res);
		exit_code = EX_SOFTWARE;
	}

	yylex_destroy();

	if (config_enabled_checks) {
		free_string_list(config_enabled_checks);
	}
	if (config_disabled_checks) {
		free_string_list(config_disabled_checks);
	}
	if (cl_enabled_checks) {
		free_string_list(cl_enabled_checks);
	}
	if (cl_disabled_checks) {
		free_string_list(cl_disabled_checks);
	}

	free_checks(ck);
	free_file_list(te_files);
	free_file_list(if_files);
	free_file_list(fc_files);
	free_file_list(context_files);

	return exit_code;
}
