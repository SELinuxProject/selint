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

extern FILE * yyin;
extern int yyparse();
struct policy_node *ast;

START_TEST (test_parse_basic_te) {

	ast = NULL;

	yyin = fopen(BASIC_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	struct policy_node *cur = ast;

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);
	
	cur = ast->next;
	ck_assert_int_eq(NODE_DECL, cur->flavor);
	struct declaration_data *dd = (struct declaration_data *)(cur->data);
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_t", dd->name);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_ptr_null(cur->first_child);

	cur = cur->next;
	ck_assert_int_eq(NODE_DECL, cur->flavor);
	dd = (struct declaration_data *)(cur->data);
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

	ast = NULL;

	yyin = fopen(BASIC_IF_FILENAME, "r");
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

	ck_assert_int_eq(NODE_IF_DEF, cur->flavor);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_str_eq("basic_domtrans", (char *) cur->data);

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

	ast = NULL;

	yyin = fopen(UNCOMMON_TE_FILENAME, "r");
	ck_assert_int_eq(0, yyparse());

	ck_assert_ptr_nonnull(ast);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(yyin);
}
END_TEST

START_TEST (test_parse_blocks) {

	ast = NULL;

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

	ast = NULL;

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
