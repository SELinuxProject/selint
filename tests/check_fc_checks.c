#include <check.h>
#include <stdlib.h>

#include "../src/fc_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_file_context_types_exist) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = "foo";
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->type = strdup("foo_t");

	node->data = entry;

	struct check_result *res = check_file_context_types_exist(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_TYPE);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	insert_into_decl_map("foo_t", "foo", DECL_TYPE);

	res = check_file_context_types_exist(data, node);

	ck_assert_ptr_null(res);

	free(res);

	free_all_maps();
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_types_in_mod) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = "foo";
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->type = strdup("foo_t");

	node->data = entry;

	struct check_result *res = check_file_context_types_in_mod(data, node);

	ck_assert_ptr_null(res);

	insert_into_decl_map("foo_t", "bar", DECL_TYPE);

	res = check_file_context_types_in_mod(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_FC_TYPE);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	data->mod_name = "bar";

	res = check_file_context_types_exist(data, node);

	ck_assert_ptr_null(res);

	free(res);

	free_all_maps();
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_error_nodes) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = "foo";
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));

	node->flavor = NODE_FC_ENTRY;

	struct check_result *res = check_file_context_error_nodes(data, node);

	ck_assert_ptr_null(res);

	node->flavor = NODE_ERROR;

	res = check_file_context_error_nodes(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_ERROR);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	free(data);
	free_policy_node(node);
}
END_TEST

Suite *fc_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("FC_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_file_context_types_exist);
	tcase_add_test(tc_core, test_check_file_context_types_in_mod);
	tcase_add_test(tc_core, test_check_file_context_error_nodes);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = fc_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
