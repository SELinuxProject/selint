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

enum selint_error run_checks_on_one_file(struct checks *ck, struct check_data *data, struct policy_node *head) {

	struct policy_node *cur = head;

	while (cur) {
		enum selint_error res = call_checks(ck, data, cur);
		if ( res != SELINT_SUCCESS) {
			return res;
		}

		if (cur->first_child) {
			cur = cur->first_child;
		} else if (cur->next) {
			cur = cur->next;
		} else {
			cur = cur->parent;
		}
	}

	return SELINT_SUCCESS;
}

enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor, struct policy_file_list *files) {

	struct policy_file_node *file = files->head;

	struct check_data data;
	data.flavor = flavor;

	while (file) {

		data.mod_name = file->file->filename;

		enum selint_error res = run_checks_on_one_file(ck, &data, file->file->ast);
		if ( res != SELINT_SUCCESS) {
			return res;
		}

		file = file->next;

	}

	return SELINT_SUCCESS;
}
