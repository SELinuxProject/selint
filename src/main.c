#include <stdio.h>
#include <getopt.h>
#include "tree.h"
#include "parse.h"
#include "config.h"

extern int yyparse();

static int verbose_flag;

struct policy_node *ast;

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

		int c = getopt_long(argc, argv, "Vvrc:m:d:e:l:", long_options, &option_index);

		if ( c == -1 ) {
			break;
		}

		switch (c) {

			//getopt returns 0 when a long option with no short equivalent is used
			case 0:
				break;

			case 'c':
				printf("Config file: %s\n", optarg);
				break;

			case 'd':
				printf("Flag d with value %s\n", optarg);
				break;

			case 'e':
				printf("Flag e with value %s\n", optarg);
				break;

			case 'l':
				printf("Flag l with value %s\n", optarg);
				break;

			case 'm':
				printf("Flag m with value %s\n", optarg);
				break;

			case 'r':
				printf("recursive\n");
				break;

			case 's':
				printf("source mode\n");
				break;

			case 'V':
				printf("Version %s\n", VERSION);
				break;

			case 'v':
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
		printf("%s\n", argv[optind++]);
	}

	yyparse();
	return 0;
}
