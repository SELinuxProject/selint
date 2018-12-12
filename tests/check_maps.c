#include <check.h>

#include "../src/maps.h"

START_TEST (test_insert_into_type_map) {

	insert_into_type_map("foo_t", "test_module");
	insert_into_type_map("bar_t", "test_module");
	insert_into_type_map("baz_t", "other_module");

	char *mod_name = look_up_in_type_map("doesntexist");

	ck_assert_ptr_null(mod_name);

	mod_name = look_up_in_type_map("foo_t");

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module");

	mod_name = look_up_in_type_map("bar_t");

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module");

	mod_name = look_up_in_type_map("baz_t");

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "other_module");

	ck_assert_int_eq(type_map_count(), 3);

	free_all_maps();
}
END_TEST

START_TEST (test_insert_into_type_map_dup) {

	insert_into_type_map("foo_t", "test_module");
	insert_into_type_map("foo_t", "other_module");

	ck_assert_int_eq(type_map_count(), 1);

	free_all_maps();
}
END_TEST

START_TEST (test_insert_decl_into_template_map) {

	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_t");
	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_exec_t");
	insert_decl_into_template_map("user_domain", DECL_ROLE, "$1_r");

	insert_decl_into_template_map("other_template", DECL_TYPE, "$1_conf_t");

	struct decl_list *dl = look_up_decl_in_template_map("doesntexist");
	ck_assert_ptr_null(dl);

	dl = look_up_decl_in_template_map("user_domain");
	ck_assert_ptr_nonnull(dl);
	ck_assert_ptr_nonnull(dl->decl);
	ck_assert_int_eq(dl->decl->flavor, DECL_TYPE);
	ck_assert_ptr_nonnull(dl->decl->name);
	ck_assert_str_eq(dl->decl->name, "$1_t");
	ck_assert_ptr_null(dl->decl->attrs);

	dl = dl->next;
	ck_assert_ptr_nonnull(dl);
	ck_assert_ptr_nonnull(dl->decl);
	ck_assert_int_eq(dl->decl->flavor, DECL_TYPE);
	ck_assert_ptr_nonnull(dl->decl->name);
	ck_assert_str_eq(dl->decl->name, "$1_exec_t");
	ck_assert_ptr_null(dl->decl->attrs);

	dl = dl->next;
	ck_assert_ptr_nonnull(dl);
	ck_assert_ptr_nonnull(dl->decl);
	ck_assert_int_eq(dl->decl->flavor, DECL_ROLE);
	ck_assert_ptr_nonnull(dl->decl->name);
	ck_assert_str_eq(dl->decl->name, "$1_r");
	ck_assert_ptr_null(dl->decl->attrs);

	ck_assert_ptr_null(dl->next);

	dl = look_up_decl_in_template_map("other_template");
	ck_assert_ptr_nonnull(dl);
	ck_assert_ptr_nonnull(dl->decl);
	ck_assert_int_eq(dl->decl->flavor, DECL_TYPE);
	ck_assert_ptr_nonnull(dl->decl->name);
	ck_assert_str_eq(dl->decl->name, "$1_conf_t");
	ck_assert_ptr_null(dl->decl->attrs);

	free_all_maps();
}
END_TEST

START_TEST (test_insert_call_into_template_map) {

	struct if_call_data *call = malloc(sizeof(struct if_call_data));

	call->name = strdup("foo");
	call->args = malloc(sizeof(struct string_list));
	call->args->string = strdup("bar_t");
	call->args->next = NULL;

	insert_call_into_template_map("user_domain", call);

	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_conf_t");

	struct if_call_list *out = look_up_call_in_template_map("user_domain");

	ck_assert_ptr_eq(call, out->call);

	free_if_call_data(call);

}
END_TEST

Suite *maps_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parsing");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_insert_into_type_map);
	tcase_add_test(tc_core, test_insert_into_type_map_dup);
	tcase_add_test(tc_core, test_insert_decl_into_template_map);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = maps_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
