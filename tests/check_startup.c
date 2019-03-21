#include <check.h>

#include "../src/startup.h"
#include "../src/maps.h"

START_TEST (test_load_access_vectors_normal) {

	load_access_vectors_normal("sample_av");

	ck_assert_int_eq(decl_map_count(DECL_CLASS), 3);
	ck_assert_int_eq(decl_map_count(DECL_PERM), 37);

	ck_assert_str_eq(look_up_in_decl_map("file", DECL_CLASS), "class");
	ck_assert_str_eq(look_up_in_decl_map("append", DECL_PERM), "perm");
	ck_assert_str_eq(look_up_in_decl_map("listen", DECL_PERM), "perm");
	ck_assert_str_eq(look_up_in_decl_map("use", DECL_PERM), "perm");

	free_all_maps();

}
END_TEST

Suite *startup_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Startup");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_load_access_vectors_normal);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = startup_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
