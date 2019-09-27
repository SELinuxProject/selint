#include <check.h>
#include <stdlib.h>

#include "../src/te_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_require_block) {
	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_REQUIRE;
	struct check_data *cd = calloc(1, sizeof(struct check_data));

	cd->flavor = FILE_IF_FILE;
	ck_assert_ptr_null(check_require_block(cd, cur));

	cd->flavor = FILE_FC_FILE;
	ck_assert_ptr_null(check_require_block(cd, cur));

	cd->flavor = FILE_TE_FILE;
	struct check_result *res = check_require_block(cd, cur);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_REQUIRE);

	free_check_result(res);

	cur->flavor = NODE_GEN_REQ;

	res = check_require_block(cd, cur);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_REQUIRE);

	free_check_result(res);
	free(cd);
	free_policy_node(cur);
}
END_TEST

START_TEST (test_check_module_if_call_in_optional) {
	struct check_result *res;

	char *foo_read_str = strdup("foo_read");
	char *bar_read_str = strdup("bar_read");

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_IF_CALL;
	struct if_call_data *if_data = calloc(1, sizeof(struct if_call_data));
	cur->data = if_data;
	if_data->name = foo_read_str;
	struct check_data *cd = calloc(1, sizeof(struct check_data));
	cd->mod_name = "baz";

	insert_into_ifs_map("foo_read", "foo");
	insert_into_mods_map("foo", "module");

	res = check_module_if_call_in_optional(cd, cur);

	ck_assert_ptr_nonnull(res);
	free_check_result(res);

	if_data->name = bar_read_str;
	insert_into_ifs_map("bar_read", "bar");
	insert_into_mods_map("bar", "base");

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	cur->parent = calloc(1, sizeof(struct policy_node));
	cur->parent->flavor = NODE_OPTIONAL_POLICY;
	cur->parent->first_child = cur;

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	if_data->name = foo_read_str;

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	free(bar_read_str);
	free(cd);
	free_all_maps();
	free_policy_node(cur->parent);
}
END_TEST

Suite *te_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("TE_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_module_if_call_in_optional);
	tcase_add_test(tc_core, test_check_require_block);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = te_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
