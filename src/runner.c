#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include "runner.h"
#include "fc_checks.h"
#include "parse_fc.h"

extern FILE * yyin;
extern int yyparse();
struct policy_node *ast; // Must be global so the parser can access it
extern int yylineno;
extern char * parsing_filename;

struct policy_node * parse_one_file(char *filename) {

	ast = NULL;
	yylineno = 1;

	yyin = fopen(filename, "r");
	parsing_filename = filename;
	yyparse();
	fclose(yyin);

	// dont run cleanup_parsing until everything is done because it frees the maps
	return ast;
}

struct checks * register_checks() {

	struct checks *ck = malloc(sizeof(struct checks));
	memset(ck, 0, sizeof(struct checks));

	// Temporarily just register all, since config files and command line check specification
	// isn't implemented yet
	add_check(NODE_FC_ENTRY, ck, check_file_context_types_exist);
	add_check(NODE_FC_ENTRY, ck, check_file_context_types_in_mod);
	add_check(NODE_ERROR, ck, check_file_context_error_nodes); 

	return ck;
}

enum selint_error parse_all_files_in_list(struct policy_file_list *files) {

	struct policy_file_node *cur = files->head;

	while (cur) {
		printf("Parsing %s\n", cur->file->filename);
		cur->file->ast = parse_one_file(cur->file->filename);
		if (!cur->file->ast) {
			return SELINT_PARSE_ERROR;
		}
		cur = cur->next;
	}

	return SELINT_SUCCESS;

}

enum selint_error parse_all_fc_files_in_list(struct policy_file_list *files) {

	struct policy_file_node *cur = files->head;

	while (cur) {
		printf("Parsing fc file %s\n", cur->file->filename);
		cur->file->ast = parse_fc_file(cur->file->filename);
		if (!cur->file->ast) {
			return SELINT_PARSE_ERROR;
		}
		cur = cur->next;
	}

	return SELINT_SUCCESS;
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
			if (cur) {
				cur = cur->next;
			}
		}
	}

	return SELINT_SUCCESS;
}

enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor, struct policy_file_list *files) {

	struct policy_file_node *file = files->head;

	struct check_data data;
	data.flavor = flavor;

	while (file) {

		data.mod_name = strdup(basename(file->file->filename));

		char *suffix_ptr = rindex(data.mod_name, '.');

		*suffix_ptr = '\0';

		enum selint_error res = run_checks_on_one_file(ck, &data, file->file->ast);
		if ( res != SELINT_SUCCESS) {
			return res;
		}

		free(data.mod_name);

		file = file->next;

	}

	return SELINT_SUCCESS;
}

enum selint_error run_analysis(struct checks *ck, struct policy_file_list *te_files, struct policy_file_list *if_files, struct policy_file_list *fc_files) {

	enum selint_error res;

	res = parse_all_files_in_list(if_files);
	if (res != SELINT_SUCCESS) {
		return res;
	}

	res = parse_all_files_in_list(te_files);
	if (res != SELINT_SUCCESS) {
		return res;
	}

	res = parse_all_fc_files_in_list(fc_files); // TODO: This needs to do fc_file parsing
	if (res != SELINT_SUCCESS) {
		return res;
	}

	// TODO template passes

	res = run_all_checks(ck, FILE_TE_FILE, te_files);
	if (res != SELINT_SUCCESS) {
		return res;
	}

	res = run_all_checks(ck, FILE_IF_FILE, if_files);
	if (res != SELINT_SUCCESS) {
		return res;
	}

	res = run_all_checks(ck, FILE_FC_FILE, fc_files);
	if (res != SELINT_SUCCESS) {
		return res;
	}

	cleanup_parsing();

	return SELINT_SUCCESS;
}
