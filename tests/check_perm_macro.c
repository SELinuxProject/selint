/*
* Copyright 2020 The SELint Contributors
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

#include "../src/startup.h"
#include "../src/maps.h"
#include "../src/selint_error.h"
#include "../src/perm_macro.h"

#define PERMS_PATH SAMPLE_POL_DIR "perms.spt"

typedef uint32_t mask_t;

extern void compute_perm_mask(const struct string_list *permissions, mask_t *mask_raw, mask_t *mask_extended);
extern unsigned short popcount(mask_t x);

START_TEST (test_permmacro_dirs) {

	enum selint_error res;
	struct string_list *permissions;
	char *check_str;
	mask_t mask_raw, mask_extended;

	// parse permission macros
	res = load_obj_perm_sets_source(PERMS_PATH);
	ck_assert_int_eq(SELINT_SUCCESS, res);

	ck_assert_ptr_null(permmacro_check("dir", NULL));

	// check 0
	permissions = sl_from_str("getattr");
	ck_assert_ptr_nonnull(permissions);

	ck_assert_ptr_null(permmacro_check("dir", permissions));

	free_string_list(permissions);

	// check 1
	permissions = sl_from_str("search_dir_perms");
	ck_assert_ptr_nonnull(permissions);

	ck_assert_ptr_null(permmacro_check("dir", permissions));

	free_string_list(permissions);

	// check 2
	permissions = sl_from_strs(2, "getattr", "search");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(2, popcount(mask_extended));
	ck_assert_ptr_null(permmacro_check("dir", permissions));

	free_string_list(permissions);

	//check 3
	permissions = sl_from_strs(3, "getattr", "search", "open");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(3, popcount(mask_raw));
	ck_assert_int_eq(3, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: search_dir_perms (replacing { getattr search open }, would add (none))", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 4
	permissions = sl_from_strs(2, "search", "open");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(3, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: search_dir_perms (replacing { search open }, would add { getattr })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 5
	permissions = sl_from_strs(2, "create", "mounton");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(4, popcount(mask_extended));
	ck_assert_ptr_null(permmacro_check("dir", permissions));

	free_string_list(permissions);

	// check 6
	permissions = sl_from_strs(5, "open", "read", "write", "remove_name", "add_name");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(5, popcount(mask_raw));
	ck_assert_int_eq(10, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: rw_dir_perms (replacing { open read write remove_name add_name }, would add { ioctl getattr lock search })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 6
	permissions = sl_from_strs(2, "search_dir_perms", "read");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(4, popcount(mask_raw));
	ck_assert_int_eq(6, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: read_dir_perms (replacing { search_dir_perms read }, would add { ioctl lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 7
	permissions = sl_from_strs(3, "search_dir_perms", "read", "quotaon");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(5, popcount(mask_raw));
	ck_assert_int_eq(7, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: read_dir_perms (replacing { search_dir_perms read }, would add { ioctl lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 7
	permissions = sl_from_strs(3, "search_dir_perms", "read", "some_new_perm");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(5, popcount(mask_raw));
	ck_assert_int_eq(7, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: read_dir_perms (replacing { search_dir_perms read }, would add { ioctl lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 8
	permissions = sl_from_strs(4, "relabel_dir_perms", "open", "read", "search");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(6, popcount(mask_raw));
	ck_assert_int_eq(8, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: read_dir_perms (replacing { open read search }, would add { ioctl lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 9
	permissions = sl_from_strs(6, "create", "open", "read", "add_name", "remove_name", "rmdir");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(6, popcount(mask_raw));
	ck_assert_int_eq(14, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: control_dir_perms (replacing { create open read add_name remove_name rmdir }, would add { ioctl write getattr setattr lock unlink link rename reparent search })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 10
	permissions = sl_from_strs(3, "search", "open", "some_new_perm");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(3, popcount(mask_raw));
	ck_assert_int_eq(4, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: search_dir_perms (replacing { search open }, would add { getattr })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 11
	permissions = sl_from_strs(3, "search", "open", "audit_access");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(3, popcount(mask_raw));
	ck_assert_int_eq(4, popcount(mask_extended));
	check_str = permmacro_check("dir", permissions);
	ck_assert_str_eq("Suggesting permission macro: search_dir_perms (replacing { search open }, would add { getattr })", check_str);

	free(check_str);
	free_string_list(permissions);

	// cleanup
	free_permmacros();
	free_all_maps();

}
END_TEST

START_TEST (test_permmacro_files) {

	enum selint_error res;
	struct string_list *permissions;
	char *check_str;
	mask_t mask_raw, mask_extended;

	// parse permission macros
	res = load_obj_perm_sets_source(PERMS_PATH);
	ck_assert_int_eq(SELINT_SUCCESS, res);

	// check 1
	ck_assert_ptr_null(permmacro_check("file", NULL));

	// check 2
	permissions = sl_from_str("getattr");
	ck_assert_ptr_nonnull(permissions);

	ck_assert_ptr_null(permmacro_check("file", permissions));

	free_string_list(permissions);

	// check 3
	permissions = sl_from_strs(3, "open", "read", "lock");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(3, popcount(mask_raw));
	ck_assert_int_eq(6, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: read_file_perms (replacing { open read lock }, would add { ioctl getattr })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 4
	permissions = sl_from_str("read_no_lock_file_perms");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(4, popcount(mask_raw));
	ck_assert_int_eq(6, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	// do not suggest read_file_perms
	ck_assert_ptr_null(check_str);

	free(check_str);
	free_string_list(permissions);

	// check 5
	permissions = sl_from_strs(2, "map", "read_file_perms");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(6, popcount(mask_raw));
	ck_assert_int_eq(7, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	// do not 'suggesting mmap_read_file_perms replacing { map } (would add (none))'
	ck_assert_ptr_null(check_str);

	free_string_list(permissions);

	// check 6
	permissions = sl_from_strs(2, "relabelfrom", "relabelto");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(3, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: relabel_file_perms (replacing { relabelfrom relabelto }, would add { getattr })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 7
	permissions = sl_from_strs(5, "open", "read", "write", "create", "unlink");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(5, popcount(mask_raw));
	ck_assert_int_eq(12, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: control_file_perms (replacing { open read write create unlink }, would add { ioctl getattr setattr lock append link rename })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 8
	permissions = sl_from_strs(2, "getattr", "rename");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(2, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: rename_file_perms (replacing { getattr rename }, would add (none))", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 9
	permissions = sl_from_strs(2, "read_file_perms", "write_file_perms");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(6, popcount(mask_raw));
	ck_assert_int_eq(8, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: rw_file_perms (replacing { read_file_perms write_file_perms }, would add (none))", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 10
	permissions = sl_from_strs(3, "read", "write", "open");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(3, popcount(mask_raw));
	ck_assert_int_eq(8, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: rw_file_perms (replacing { read write open }, would add { ioctl getattr lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 11
	permissions = sl_from_strs(2, "read", "write");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(2, popcount(mask_raw));
	ck_assert_int_eq(7, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: rw_no_open_file_perms (replacing { read write }, would add { ioctl getattr lock })", check_str);

	free(check_str);
	free_string_list(permissions);

	// check 12
	permissions = sl_from_strs(3, "read_file_perms", "relabelfrom", "relabelto");
	ck_assert_ptr_nonnull(permissions);
	mask_raw = mask_extended = 0;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	ck_assert_int_eq(7, popcount(mask_raw));
	ck_assert_int_eq(8, popcount(mask_extended));
	check_str = permmacro_check("file", permissions);
	ck_assert_str_eq("Suggesting permission macro: relabel_file_perms (replacing { relabelfrom relabelto }, would add (none))", check_str);

	free(check_str);
	free_string_list(permissions);

	// cleanup
	free_permmacros();
	free_all_maps();

}
END_TEST

Suite *startup_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Permmacro");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_permmacro_dirs);
	tcase_add_test(tc_core, test_permmacro_files);
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
