#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <confuse.h>

#include "runner.h"
#include "tree.h"
#include "parse.h"
#include "config.h"
#include "file_list.h"
#include "util.h"

extern int yyparse();

extern int verbose_flag;

int main(int argc, char **argv) {

	char severity = '\0';
	char *config_filename = NULL;

	cfg_opt_t opts[] =
	{
		CFG_STR("severity", "convention", CFGF_NONE),
		CFG_END()
	};
	cfg_t *cfg;
	cfg = cfg_init(opts, CFGF_NONE);

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
				printf("Flag d with value %s\n", optarg);
				break;

			case 'e':
				// Enable a given check
				printf("Flag e with value %s\n", optarg);
				break;

			case 'h':
				// Display usage info and exit
				printf("Flag h called");
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
				printf("recursive\n");
				break;

			case 's':
				// Run in source mode
				printf("source mode\n");
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
	if (config_filename) {
		print_if_verbose("Loading configuration from: %s\n", config_filename);
		if (cfg_parse(cfg, config_filename) == CFG_PARSE_ERROR) {
			printf("Parse error when attempting to parse configuration file.\n");
			return -1;
		}
	}

	if (!severity) {
		if (config_filename) {
			// Not specified on command line.  Read from config
			char *config_severity = cfg_getstr(cfg, "severity");
			printf("severity: %s\n", config_severity);

			if (strcmp(config_severity, "convention") == 0) {
				severity = 'C';
			} else if (strcmp(config_severity, "style") == 0) {
				severity = 'S';
			} else if (strcmp(config_severity, "warning") == 0) {
				severity = 'W';
			} else if (strcmp(config_severity, "error") == 0) {
				severity = 'E';
			} else if (strcmp(config_severity, "fatal") == 0) {
				severity = 'F';
			} else {
				printf("Invalid severity level (%s) specified in config.  Options are \"convention\", \"style\", \"warning\", \"error\" and \"fatal\"", config_severity);
				return -1;
			}
		} else {
			severity = 'C';
		}
	}

	print_if_verbose("Severity level set to %c\n", severity);

	if (optind == argc) {
		printf("TODO: usage message\n");
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
	while (optind + i < argc ) {
		paths[i++] = argv[optind];
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
		}

		file = fts_read(ftsp);
	}

	fts_close(ftsp);
	free(paths);

	struct policy_file_node *cur = te_files->head;
	while (cur) {
		cur = cur->next;
	}

	struct checks *ck = register_checks(severity);
	if (!ck) {
		printf("Failed to register checks (bad configuration)\n");
		return -1;
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

	cfg_free(cfg);

	free_checks(ck);

	free_file_list(te_files);
	free_file_list(if_files);
	free_file_list(fc_files);

/*
		struct policy_node *ast = parse_one_file(argv[optind]);

		if(ast) {	
			printf("Successfully parsed %s\n", argv[optind]);
		} else {
			printf("Error parsing %s\n", argv[optind]);
		}
		optind++;
		
		file_list_push_back(	
	}

*/	

	return 0;
}
