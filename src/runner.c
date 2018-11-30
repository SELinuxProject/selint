#include <stdio.h>

#include "runner.h"

extern FILE * yyin;
extern int yyparse();
struct policy_node *ast; // Must be global so the parser can access it
extern int yylineno;

struct policy_node * parse_one_file(char *filename) {

	ast = NULL;
	yylineno = 1;

	yyin = fopen(filename, "r");
	yyparse();
	fclose(yyin);

	// dont run cleanup_parsing until everything is done because it frees the maps
	return ast;
}
