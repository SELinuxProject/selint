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

// ASCII characters go up to 127
#define CONTEXT_ID 128

extern int yydebug;

extern int yylex_destroy(void);

extern int verbose_flag;

static void usage(void)
{

	/* *INDENT-OFF* */
	printf("Usage: selint [OPTIONS] FILE [...]\n"\
		"Perform static code analysis on SELinux policy source.\n\n");
	printf("  -c, --config=CONFIGFILE\tOverride default config with config\n"\
		"\t\t\t\tspecified on command line.  See\n"\
		"\t\t\t\tCONFIGURATION section for config file syntax.\n"\
		"      --context=CONTEXT_PATH\tRecursively scan CONTEXT_PATH to find additional te and if\n"\
		"\t\t\t\tfiles to parse, but not scan.  SELint will assume the scanned policy files\n"\
		"\t\t\t\tare intended to be compiled together with the context files\n"\
		"  -d, --disable=CHECKID\t\tDisable check with the given ID.\n"\
		"  -e, --enable=CHECKID\t\tEnable check with the given ID.\n"\
		"  -E, --only-enabled\t\tOnly run checks that are explicitly enabled with\n"\
		"\t\t\t\tthe --enable option.\n"\
		"  -F, --fail\t\t\tExit with a non-zero value if any issue was found\n"\
		"  -h, --help\t\t\tDisplay this menu\n"\
		"  -l, --level=LEVEL\t\tOnly list errors with a severity level at or\n"\
		"\t\t\t\tgreater than LEVEL.  Options are C (convention), S (style),\n"\
		"\t\t\t\tW (warning), E (error), F (fatal error).\n"\
		"  -s, --source\t\t\tRun in \"source mode\" to scan a policy source repository\n"\
		"\t\t\t\tthat is designed to compile into a full system policy.\n"\
		"  -S, --summary\t\t\tDisplay a summary of issues found after running the analysis\n"\
		"  -r, --recursive\t\tScan recursively and check all SELinux policy files found.\n"\
		"  -v, --verbose\t\t\tEnable verbose output\n"\
		"  -V, --version\t\t\tShow version information and exit.\n"
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
	int summary_flag = 0;
	int fail_on_finding = 0;
	char *context_path = NULL;

	struct string_list *config_disabled_checks = NULL;
	struct string_list *config_enabled_checks = NULL;
	struct string_list *cl_disabled_checks = NULL;
	struct string_list *cl_enabled_checks = NULL;

	struct string_list *cl_e_cursor = NULL;
	struct string_list *cl_d_cursor = NULL;

	yydebug = 0;

	while (1) {

		static struct option long_options[] = {
			{ "config",       required_argument, NULL,          'c' },
			{ "context",      required_argument,  NULL,          CONTEXT_ID },
			{ "disable",      required_argument, NULL,          'd' },
			{ "enable",       required_argument, NULL,          'e' },
			{ "fail",         no_argument,       NULL,          'F' },
			{ "only-enabled", no_argument,       NULL,          'E' },
			{ "help",         no_argument,       NULL,          'h' },
			{ "level",        required_argument, NULL,          'l' },
			{ "modules-conf", required_argument, NULL,          'm' },
			{ "recursive",    no_argument,       NULL,          'r' },
			{ "source",       no_argument,       NULL,          's' },
			{ "summary",      no_argument,       NULL,          'S' },
			{ "version",      no_argument,       NULL,          'V' },
			{ "verbose",      no_argument,       &verbose_flag, 1   },
			{ 0,              0,                 0,             0   }
		};

		int option_index = 0;

		int c = getopt_long(argc,
		                    argv,
		                    "c:d:e:EFhl:mrsSVv",
		                    long_options,
		                    &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {

		case 0:
			break;

		case 'c':
			// Specify config file
			config_filename = optarg;
			break;

		case CONTEXT_ID:
			// Specify a path for context files
			context_path = optarg;
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

		case 'F':
			// Exit non-zero if any issue was found
			fail_on_finding = 1;
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

		case 'S':
			// Display a summary at the end of the run
			summary_flag = 1;
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

	struct config_check_data ccd;

	if (config_filename) {
		char cfg_severity;
		if (SELINT_SUCCESS != parse_config(config_filename, source_flag,
		                                   &cfg_severity, &config_disabled_checks,
		                                   &config_enabled_checks, &ccd)) {
			// Error message printed by parse_config()
			exit(EX_CONFIG);
		}
		if (severity == '\0') {
			severity = cfg_severity;
		}
	} else {
		// If there is no config, we should assume the existance of normal users and
		// roles that we wouldn't otherwise know about
		insert_into_decl_map("system_u", "__assumed__", DECL_USER);
		insert_into_decl_map("object_r", "__assumed__", DECL_ROLE);
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
	
	if (only_enabled && !cl_enabled_checks) {
		printf("Error: no warning enabled!\n");
		exit(EX_USAGE);
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

	struct policy_file_list *context_te_files =
		calloc(1, sizeof(struct policy_file_list));

	struct policy_file_list *context_if_files =
		calloc(1, sizeof(struct policy_file_list));

	char **paths = malloc(sizeof(char *) * argc - optind + 2);

	int i = 0;
	while (optind < argc) {
		paths[i++] = argv[optind++];
	}

	paths[i] = NULL;

	FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);

	FTSENT *file = fts_read(ftsp);

	char *modules_conf_path = NULL;

	while (file) {
		const char *suffix = (file->fts_pathlen > 3) ? (file->fts_path + file->fts_pathlen - 3) : NULL;

		if (suffix && !strcmp(suffix, ".te")) {
			file_list_push_back(te_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
		} else if (suffix && !strcmp(suffix, ".if")) {
			file_list_push_back(if_files,
			                    make_policy_file(file->fts_path,
			                                     NULL));
			char *mod_name = strdup(file->fts_name);
			mod_name[file->fts_namelen - 3] = '\0';
			insert_into_mod_layers_map(mod_name, file->fts_parent->fts_name);
			free(mod_name);
		} else if (suffix && !strcmp(suffix, ".fc")) {
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

	if (context_path) {
		paths[0] = context_path;
		paths[1] = NULL;

		ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);
		file = fts_read(ftsp);

		while (file) {
			const char *suffix = (file->fts_pathlen > 3) ? (file->fts_path + file->fts_pathlen - 3) : NULL;
			if (suffix &&  !strcmp(suffix, ".te")) {
				if (!file_name_in_file_list(file->fts_path, te_files)) {
					file_list_push_back(context_te_files,
							    make_policy_file(file->fts_path,
							    NULL));
				}
			} else if (suffix &&  !strcmp(suffix, ".if")) {
				if (!file_name_in_file_list(file->fts_path, if_files)) {
					file_list_push_back(context_if_files,
							    make_policy_file(file->fts_path,
							    NULL));
				}
			} else if (source_flag
                                   && !modules_conf_path
                                   && 0 == strcmp(file->fts_name, "modules.conf")) {
				modules_conf_path = strdup(file->fts_path);
			}
			file = fts_read(ftsp);
		}
	}

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
		free_file_list(context_te_files);
		free_file_list(context_if_files);
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
		enum selint_error res = load_devel_headers(context_if_files);
		if (res != SELINT_SUCCESS) {
			printf("Error loading SELinux development header files.\n");
		}
	}

	free(modules_conf_path);

	enum selint_error res = run_analysis(ck, te_files, if_files, fc_files, context_te_files, context_if_files, &ccd);
	switch (res) {
	case SELINT_SUCCESS:
		if (summary_flag) {
			display_run_summary(ck);
		}
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
	free_file_list(context_te_files);
	free_file_list(context_if_files);

	if (fail_on_finding && found_issue && exit_code == EX_OK) {
		return EX_DATAERR;
	}

	return exit_code;
}
