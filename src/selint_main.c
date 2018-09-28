#include <stdio.h>
#include <getopt.h>
#include "selint_parse.h"

extern int yyparse();

static int verbose_flag;

int main(int argc, char **argv) {

	while (1) {

		static struct option long_options[] = 
			{
				{ "version", no_argument, NULL, 'V' },
				{ "verbose", no_argument, &verbose_flag, 1 },
				{ "help", no_argument, NULL, 'h' },
				{ "recursive", no_argument, NULL, 'r' },
				{ "config", required_argument, NULL, 'c' },
				{ "modules-conf", required_argument, NULL, 'm' },
				{ "disable", required_argument, NULL, 'd' },
				{ "enable", required_argument, NULL, 'e' },
				{ "level", required_argument, NULL, 'l' },
				{ 0, 0, 0, 0 }
			};

		int option_index = 0;

		int c = getopt_long(argc, argv, "Vvrc:m:d:e:l:", long_options, &option_index);

		if ( c == -1 ) {
			break;
		}

		switch (c) {

			case 0:
				break;

			case 'V':
				printf("Version\n");
				break;

			case 'v':
				verbose_flag = 1;
				break;

			case 'r':
				printf("recursive\n");
				break;

			case 'c':
				printf("Config file: %s\n", optarg);
				break;

			case 'm':
				printf("Flag m with value %s\n", optarg);
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
