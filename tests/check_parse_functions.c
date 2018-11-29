#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "../src/parse_functions.h"
#include "../src/maps.h"

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
	ck_assert_str_eq(cur->data, "example");
	ck_assert_str_eq(get_current_module_name(), "example");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur));

	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_declaration_type) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;
	cur->parent = NULL; 
	cur->data = NULL;
	cur->first_child = NULL;
	cur->next = NULL;

	struct policy_node *prev = cur;

	set_current_module_name("test");

	ck_assert_int_eq(SELINT_SUCCESS, insert_declaration(&cur, "type", "foo_t"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_eq(cur->prev, prev);
	ck_assert_int_eq(cur->flavor, NODE_DECL);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(prev->first_child);
	ck_assert_ptr_nonnull((struct declation *) cur->data);
	ck_assert_int_eq(((struct declaration_data *)cur->data)->flavor, DECL_TYPE);
	ck_assert_str_eq(((struct declaration_data *)cur->data)->name, "foo_t");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(prev));

	// TODO attributes

	char *mn = look_up_in_type_map("foo_t");

	ck_assert_ptr_nonnull(mn);

	cleanup_parsing();	
}
END_TEST

START_TEST (test_insert_av_rule) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_av_rule(&cur, AV_RULE_AUDITALLOW, NULL, NULL, NULL, NULL));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_AV_RULE, cur->flavor);
	struct av_rule_data *avd = (struct av_rule_data *)(cur->data);
	ck_assert_int_eq(AV_RULE_AUDITALLOW, avd->flavor);
	ck_assert_ptr_null(avd->sources);
	ck_assert_ptr_null(avd->targets);
	ck_assert_ptr_null(avd->object_classes);
	ck_assert_ptr_null(avd->perms);

	free_policy_node(head);

	cleanup_parsing();


}
END_TEST

START_TEST (test_insert_type_transition) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_type_transition(&cur, NULL, NULL, NULL, "example_tmp_t", "filename.txt"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TT_RULE, cur->flavor);
	struct type_transition_data *ttd = (struct type_transition_data *)(cur->data);
	ck_assert_ptr_null(ttd->sources);
	ck_assert_ptr_null(ttd->targets);
	ck_assert_ptr_null(ttd->object_classes);
	ck_assert_str_eq("example_tmp_t", ttd->default_type);
	ck_assert_str_eq("filename.txt", ttd->name);

	free_policy_node(head);

	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_interface_call) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	struct string_list *args = malloc(sizeof(struct string_list));
	args->string = strdup("foo_t");
	args->next = malloc(sizeof(struct string_list));
	args->next->string = strdup("bar_t");
	args->next->next = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, insert_interface_call(&cur, "do_things", args));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_IF_CALL, cur->flavor);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_nonnull(cur->prev);

	struct if_call_data *if_data = cur->data;

	ck_assert_str_eq("do_things", if_data->name);
	ck_assert_str_eq("foo_t", if_data->args->string);
	ck_assert_str_eq("bar_t", if_data->args->next->string);

	free_policy_node(head);
	cleanup_parsing();

}
END_TEST

START_TEST (test_optional_policy) {

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

	ck_assert_int_eq(SELINT_SUCCESS, end_optional_policy(&cur));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_OPTIONAL_POLICY);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_ptr_null(cur->first_child->prev);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();
}
END_TEST

START_TEST (test_interface_def) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_interface_def(&cur, NODE_IF_DEF, "foo_read_conf"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_nonnull(cur->parent);
	ck_assert_ptr_eq(cur->parent->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_START_BLOCK);
	ck_assert_int_eq(cur->parent->flavor, NODE_IF_DEF);
	ck_assert_ptr_eq(cur->parent->first_child, cur);
	ck_assert_str_eq(cur->parent->data, "foo_read_conf");
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(cur->parent->next);

	ck_assert_int_eq(SELINT_SUCCESS, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_BAD_ARG, begin_interface_def(&cur, NODE_DECL, "foo_read_conf"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_IF_DEF);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_ptr_null(cur->first_child->prev);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();
}
END_TEST

START_TEST (test_wrong_block_end) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_optional_policy(&cur));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, begin_interface_def(&cur, NODE_IF_DEF, "sample_interface"));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_gen_require(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();

}
END_TEST

Suite *parse_functions_suite(void) {
	Suite *s;
	TCase *tc_core, *tc_blocks;

	s = suite_create("Parse_Functions");

	tc_core = tcase_create("Core");
	tc_blocks = tcase_create("Blocks");

	tcase_add_test(tc_core, test_begin_parsing_te);
	tcase_add_test(tc_core, test_insert_declaration_type);
	tcase_add_test(tc_core, test_insert_av_rule);
	tcase_add_test(tc_core, test_insert_type_transition);
	tcase_add_test(tc_core, test_insert_interface_call);
	suite_add_tcase(s, tc_core);

	tcase_add_test(tc_blocks, test_optional_policy);
	tcase_add_test(tc_blocks, test_interface_def);
	tcase_add_test(tc_blocks, test_wrong_block_end);
	suite_add_tcase(s, tc_blocks);

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
