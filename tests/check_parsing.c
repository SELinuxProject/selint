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

#include <check.h>
#include <stdio.h>

#include "../src/tree.h"
#include "../src/parse.h"
#include "../src/parse_functions.h"

#define POLICIES_DIR "sample_policy_files/"
#define BASIC_TE_FILENAME POLICIES_DIR "basic.te"
#define BASIC_IF_FILENAME POLICIES_DIR "basic.if"
#define UNCOMMON_TE_FILENAME POLICIES_DIR "uncommon.te"
#define BLOCKS_TE_FILENAME POLICIES_DIR "blocks.te"
#define EMPTY_TE_FILENAME POLICIES_DIR "empty.te"
#define SYNTAX_ERROR_FILENAME POLICIES_DIR "syntax_error.te"
#define BAD_RA_FILENAME POLICIES_DIR "bad_role_allow.te"
#define DISABLE_COMMENT_FILENAME POLICIES_DIR "disable_comment.te"

extern FILE * yyin;
extern int yyparse();
extern int yyrestart();
struct policy_node *ast;
struct policy_node *cur;
extern char *parsing_filename;

START_TEST (test_parse_basic_te) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	ast->flavor = NODE_TE_FILE;
	set_current_module_name("basic");

	yyin = fopen(BASIC_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	struct policy_node *cur = ast;

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);
	
	cur = ast->next;
	ck_assert_int_eq(NODE_DECL, cur->flavor);
	struct declaration_data *dd = cur->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_t", dd->name);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);

	cur = cur->next;
	ck_assert_int_eq(NODE_DECL, cur->flavor);
	dd = cur->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_exec_t", dd->name);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);

	cur = cur->next;
	ck_assert_int_eq(NODE_AV_RULE, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);

	cur = cur->next;
	ck_assert_int_eq(NODE_OPTIONAL_POLICY, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_nonnull(cur->first_child);

	cur = cur->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, cur->flavor);

	ck_assert_str_eq("basic", look_up_in_decl_map("basic_t", DECL_TYPE));
	ck_assert_int_eq(2, decl_map_count(DECL_TYPE));

	free_policy_node(ast);

	cleanup_parsing();

	fclose(yyin);

}
END_TEST

START_TEST (test_parse_basic_if) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	ast->flavor = NODE_IF_FILE;
	set_current_module_name("basic");

	yyin = fopen(BASIC_IF_FILENAME, "r");
	parsing_filename = "basic";
	ck_assert_int_eq(0, yyparse());

	struct policy_node *cur = ast;

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_IF_FILE, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(NODE_COMMENT, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(NODE_COMMENT, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);


	cur = cur->next;

	ck_assert_int_eq(NODE_INTERFACE_DEF, cur->flavor);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_str_eq("basic_domtrans", cur->data.str);

	cur = cur->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_GEN_REQ);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_nonnull(cur->prev);

	cur = cur->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(NODE_DECL, cur->flavor);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_nonnull(cur->prev);
	ck_assert_ptr_nonnull(cur->parent);

	cur = cur->parent->next;

	ck_assert_int_eq(NODE_IF_CALL, cur->flavor);
	ck_assert_ptr_nonnull(cur->parent); 

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);

}
END_TEST

START_TEST (test_parse_uncommon_constructs) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("uncommon");

	yyin = fopen(UNCOMMON_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	ck_assert_ptr_nonnull(ast);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);
}
END_TEST

START_TEST (test_parse_blocks) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("blocks");

	yyin = fopen(BLOCKS_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	ck_assert_ptr_nonnull(ast);

	struct policy_node *cur = ast;

	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);

	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_OPTIONAL_POLICY, cur->flavor);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_nonnull(cur->first_child);

	cur = cur->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, cur->flavor);
	ck_assert_ptr_null(cur->next);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);
}
END_TEST

START_TEST (test_parse_empty_file) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("empty");

	yyin = fopen(EMPTY_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	ck_assert_ptr_nonnull(ast);

	ck_assert_int_eq(NODE_EMPTY, ast->flavor);
	ck_assert_ptr_null(ast->next);
	ck_assert_ptr_null(ast->first_child);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);

}
END_TEST

START_TEST (test_syntax_error) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("syntax_error");

	yyin = fopen(SYNTAX_ERROR_FILENAME, "r");
	ck_assert_int_eq(1, yyparse());

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);

}
END_TEST

START_TEST (test_parse_bad_role_allow) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("bad_ra");

	yyin = fopen(BAD_RA_FILENAME, "r");
	yyrestart(yyin);
	ck_assert_int_eq(1, yyparse());

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);

}
END_TEST

START_TEST (test_disable_comment) {

	ast = cur = calloc(1, sizeof(struct policy_node));
	set_current_module_name("disable_comment");

	yyin = fopen(DISABLE_COMMENT_FILENAME, "r");
	yyrestart(yyin);
	ck_assert_int_eq(0, yyparse());

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(NODE_TE_FILE, ast->flavor);
	ck_assert_ptr_nonnull(ast->next);
	ck_assert_int_eq(NODE_DECL, ast->next->flavor);
	ck_assert_ptr_nonnull(ast->next->next);
	ck_assert_int_eq(NODE_AV_RULE, ast->next->next->flavor);
	ck_assert_str_eq("W-001\n", ast->next->next->exceptions);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);

}
END_TEST

Suite *parsing_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parsing");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_basic_te);
	tcase_add_test(tc_core, test_parse_basic_if);
	tcase_add_test(tc_core, test_parse_uncommon_constructs);
	tcase_add_test(tc_core, test_parse_blocks);
	tcase_add_test(tc_core, test_parse_empty_file);
	tcase_add_test(tc_core, test_syntax_error);
	tcase_add_test(tc_core, test_parse_bad_role_allow);
	tcase_add_test(tc_core, test_disable_comment);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = parsing_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
