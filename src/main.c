#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include "runner.h"
#include "parse.h"
#include "config.h"
#include "file_list.h"
#include "util.h"
#include "selint_config.h"
#include "startup.h"

extern int yyparse();

extern int verbose_flag;

void usage() {

	printf("Usage: selint [OPTIONS] [FILE] [...]\n"\
		"Perform static code analysis on SELinux policy source.\n\n");
	printf("  -c CONFIGFILE, --config=CONFIGFILE\tOverride default config with config\n"\
		"\t\t\t\t\tspecified on command line.  See\n"\
		"\t\t\t\t\tCONFIGURATION section for config file syntax.\n"\
		"  -d CHECKID, --disable=CHECKID\t\tDisable check with the given ID.\n"\
		"  -e CHECKID, --enable=CHECKID\t\tEnable check with the given ID.\n"\
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

}

int main(int argc, char **argv) {

	char severity = '\0';
	char *config_filename = NULL;
	int source_flag = 0;
	int recursive_scan = 0;

	struct string_list *config_disabled_checks = NULL;
	struct string_list *config_enabled_checks = NULL;
	struct string_list *cl_disabled_checks = NULL;
	struct string_list *cl_enabled_checks = NULL;

	struct string_list *cl_e_cursor = NULL;
	struct string_list *cl_d_cursor = NULL;

	while (1) {

		static struct option long_options[] = 
			{
				{ "config", required_argument, NULL, 'c' },
				{ "disable", required_argument, NULL, 'd' },
				{ "enable", required_argument, NULL, 'e' },
				{ "help", no_argument, NULL, 'h' },
				{ "level", required_argument, NULL, 'l' },
				{ "modules-conf", required_argument, NULL, 'm' },
				{ "recursive", no_argument, NULL, 'r' },
				{ "source", no_argument, NULL, 's' },
				{ "version", no_argument, NULL, 'V' },
				{ "verbose", no_argument, &verbose_flag, 1 },
				{ 0, 0, 0, 0 }
			};

		int option_index = 0;

		int c = getopt_long(argc, argv, "c:d:e:hl:mrsVv", long_options, &option_index);

		if ( c == -1 ) {
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
				if (cl_d_cursor) {
					cl_d_cursor->next = calloc(1, sizeof(struct string_list));
					cl_d_cursor = cl_d_cursor->next;
				} else {
					cl_d_cursor = calloc(1, sizeof(struct string_list));
					cl_disabled_checks = cl_d_cursor;
				}
				cl_d_cursor->string = strdup(optarg);
				break;

			case 'e':
				// Enable a given check
				if (cl_e_cursor) {
					cl_e_cursor->next = calloc(1, sizeof(struct string_list));
					cl_e_cursor = cl_e_cursor->next;
				} else {
					cl_e_cursor = calloc(1, sizeof(struct string_list));
					cl_enabled_checks = cl_e_cursor;
				}
				cl_e_cursor->string = strdup(optarg);
				break;

			case 'h':
				// Display usage info and exit
				usage();
				exit(0);
				break;

			case 'l':
				// Set the severity level
				severity = optarg[0];
				break;

			case 'm':
				// Specify a modules.conf file.  (Not in the README)
				printf("Flag m with value %s\n", optarg);
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
				printf("SELint Version %s\n", VERSION);
				exit(0);
				break;

			case 'v':
				// Run in verbose mode
				verbose_flag = 1;
				break;

			case '?':
				printf("Unrecognized option\n");
		}

	}

	print_if_verbose("Verbose mode enabled\n");

	if (source_flag) {
		print_if_verbose("Source mode enabled\n");
	}
	if (config_filename) {
		char cfg_severity;
		parse_config(config_filename, source_flag, &cfg_severity, &config_disabled_checks, &config_enabled_checks);
		if (severity != '\0') {
			severity = cfg_severity;
		}
	}

	if (!severity) {
		severity = 'C';
	}

	print_if_verbose("Severity level set to %c\n", severity);

	if (optind == argc) {
		usage();
		exit(0);
	}

	struct policy_file_list *te_files = malloc(sizeof(struct policy_file_list));
	memset(te_files, 0, sizeof(struct policy_file_list));
	struct policy_file_list *if_files = malloc(sizeof(struct policy_file_list));
	memset(if_files, 0, sizeof(struct policy_file_list));
	struct policy_file_list *fc_files = malloc(sizeof(struct policy_file_list));
	memset(fc_files, 0, sizeof(struct policy_file_list));

	char **paths = malloc (sizeof(char*) * argc - optind + 1);

	int i = 0;
	while (optind < argc ) {
		paths[i++] = argv[optind++];
	}

	paths[i] = NULL;

	FTS *ftsp = fts_open(paths, FTS_PHYSICAL | FTS_NOSTAT, NULL);

	FTSENT *file = fts_read(ftsp);

	while ( file ) {

		char *suffix = file->fts_path + file->fts_pathlen - 3;

		if (!strcmp(suffix, ".te")) {
			file_list_push_back(te_files, make_policy_file(file->fts_path, NULL));
		} else if ( !strcmp(suffix, ".if")) {
			file_list_push_back(if_files, make_policy_file(file->fts_path, NULL));
		} else if ( !strcmp(suffix, ".fc")) {
			file_list_push_back(fc_files, make_policy_file(file->fts_path, NULL));
		} else {
			print_if_verbose("Skipping %s which is not a policy file\n", file->fts_path);
			if (!recursive_scan) {
				fts_set(ftsp, file, FTS_SKIP);
			}
		}

		file = fts_read(ftsp);
	}

	fts_close(ftsp);

	free(paths);

	struct checks *ck = register_checks(severity, config_enabled_checks, config_disabled_checks, cl_enabled_checks, cl_disabled_checks);
	if (!ck) {
		printf("Failed to register checks (bad configuration)\n");
		return -1;
	}

	// Load object classes and permissions
	if (source_flag) {
		load_access_vectors_source();
	} else {
		load_access_vectors_normal("/sys/fs/selinux/class"); // TODO
	}

	enum selint_error res = run_analysis(ck, te_files, if_files, fc_files);
	switch (res) {
		case SELINT_SUCCESS:
			break;
		case SELINT_PARSE_ERROR:
			printf("Error during parsing\n");
			break;
		default:
			printf("Internal error: %d\n", res);
	}

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

	return 0;
}
