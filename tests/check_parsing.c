#include <check.h>
#include <stdio.h>

#include "../src/tree.h"
#include "../src/parse.h"
#include "../src/parse_functions.h"

#define POLICIES_DIR "sample_policy_files/"
#define BASIC_TE_FILENAME POLICIES_DIR "basic.te"
#define BASIC_IF_FILENAME POLICIES_DIR "basic.if"

extern FILE * yyin;
extern int yyparse();
struct policy_node *ast;

START_TEST (test_parse_basic_te) {

	ast = NULL;

	yyin = fopen(BASIC_TE_FILENAME, "r");
	yyparse(); 

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

	cleanup_parsing();

	fclose(yyin);

}
END_TEST

START_TEST (test_parse_basic_if) {

	ast = NULL;

	yyin = fopen(BASIC_IF_FILENAME, "r");
	yyparse();

	struct policy_node *cur = ast;

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_IF_FILE, cur->flavor);
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
