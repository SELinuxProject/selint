#include <stdio.h>
#include <getopt.h>
#include "runner.h"
#include "tree.h"
#include "parse.h"
#include "config.h"

extern int yyparse();

static int verbose_flag;

int main(int argc, char **argv) {

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
				printf("Config file: %s\n", optarg);
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
				printf("Flag l with value %s\n", optarg);
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

	if (verbose_flag) {
		printf("Verbose mode\n");
	}

	while (optind < argc ) {
		struct policy_node *ast = parse_one_file(argv[optind]);

		if(ast) {	
			printf("Successfully parsed %s\n", argv[optind]);
		} else {
			printf("Error parsing %s\n", argv[optind]);
		}
		optind++;
	}

	return 0;
}
