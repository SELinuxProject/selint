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

Suite *maps_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parsing");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_insert_into_type_map);
	tcase_add_test(tc_core, test_insert_into_type_map_dup);
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
