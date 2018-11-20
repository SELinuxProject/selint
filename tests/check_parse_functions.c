#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "../src/parse_functions.h"

#define EXAMPLE_TYPE_1 "foo_t"
#define EXAMPLE_TYPE_2 "bar_t"
#define EXAMPLE_TYPE_3 "baz_t"

START_TEST (test_begin_parsing_te) {

	struct policy_node *cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_parsing_te(&cur, "example"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_str_eq(cur->data.string, "example");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur));

}
END_TEST

START_TEST (test_insert_declaration_type) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;
	cur->parent = (struct policy_node *) 0xdeadbeef;

	struct policy_node *prev = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_declaration(&cur, "type", "foo_t"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->parent, (void *) 0xdeadbeef);
	ck_assert_ptr_eq(cur->prev, prev);
	ck_assert_int_eq(cur->flavor, NODE_DECL);
	ck_assert_ptr_nonnull((struct declation *) cur->data.decl);
	ck_assert_int_eq(cur->data.decl->flavor, DECL_TYPE);
	ck_assert_str_eq(cur->data.decl->name, "foo_t");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(prev));

	// TODO attributes
	
}
END_TEST

START_TEST (test_begin_optional_policy) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_optional_policy(&cur));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_nonnull(cur->parent);
	ck_assert_ptr_eq(cur->parent->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_START_BLOCK);
	ck_assert_int_eq(cur->parent->flavor, NODE_OPTIONAL_POLICY);
	ck_assert_ptr_eq(cur->parent->first_child, cur);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(cur->parent->next);
}
END_TEST

Suite *parse_functions_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parse_Functions");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_begin_parsing_te);
	tcase_add_test(tc_core, test_insert_declaration_type);
	tcase_add_test(tc_core, test_begin_optional_policy);
	suite_add_tcase(s, tc_core);

	return s;
}
int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = parse_functions_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
