/*
* Copyright 2019 Tresys Technology, LLC
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

#include "../src/maps.h"

START_TEST (test_insert_into_type_map) {

	insert_into_decl_map("foo_t", "test_module", DECL_TYPE);
	insert_into_decl_map("bar_t", "test_module", DECL_TYPE);
	insert_into_decl_map("baz_t", "other_module", DECL_TYPE);

	const char *mod_name = look_up_in_decl_map("doesntexist", DECL_TYPE);

	ck_assert_ptr_null(mod_name);

	mod_name = look_up_in_decl_map("foo_t", DECL_TYPE);

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module");

	mod_name = look_up_in_decl_map("bar_t", DECL_TYPE);

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module");

	mod_name = look_up_in_decl_map("baz_t", DECL_TYPE);

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "other_module");

	ck_assert_int_eq(decl_map_count(DECL_TYPE), 3);

	free_all_maps();
}
END_TEST

START_TEST (test_insert_into_type_map_dup) {

	insert_into_decl_map("foo_t", "test_module", DECL_TYPE);
	insert_into_decl_map("foo_t", "other_module", DECL_TYPE);

	ck_assert_int_eq(decl_map_count(DECL_TYPE), 1);

	free_all_maps();
}
END_TEST

START_TEST (test_role_and_user_maps) {

	insert_into_decl_map("foo_r", "test_module1", DECL_ROLE);
	insert_into_decl_map("bar_r", "test_module2", DECL_ROLE);
	insert_into_decl_map("bar_u", "test_module3", DECL_USER);

	const char *mod_name = look_up_in_decl_map("foo_r", DECL_TYPE);

	ck_assert_ptr_null(mod_name);

	mod_name = look_up_in_decl_map("foo_r", DECL_ROLE);

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module1");

	mod_name = look_up_in_decl_map("foo_r", DECL_ATTRIBUTE);

	ck_assert_ptr_null(mod_name);

	mod_name = look_up_in_decl_map("bar_u", DECL_ROLE);

	ck_assert_ptr_null(mod_name);

	mod_name = look_up_in_decl_map("bar_u", DECL_USER);

	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq(mod_name, "test_module3");

	ck_assert_int_eq(decl_map_count(DECL_TYPE), 0);
	ck_assert_int_eq(decl_map_count(DECL_ROLE), 2);
	ck_assert_int_eq(decl_map_count(DECL_USER), 1);

	free_all_maps();

}
END_TEST

START_TEST (test_class_and_perm_maps) {

	insert_into_decl_map("file", "class", DECL_CLASS);
	insert_into_decl_map("read", "perm", DECL_PERM);

	const char *res = look_up_in_decl_map("dir", DECL_CLASS);

	ck_assert_ptr_null(res);

	res = look_up_in_decl_map("file", DECL_CLASS);

	ck_assert_ptr_nonnull(res);

	res = look_up_in_decl_map("read", DECL_PERM);

	ck_assert_ptr_nonnull(res);

	ck_assert_int_eq(decl_map_count(DECL_CLASS), 1);
	ck_assert_int_eq(decl_map_count(DECL_PERM), 1);

	free_all_maps();
}
END_TEST

START_TEST (test_mods_map) {

	insert_into_mods_map("systemd", "base");
	insert_into_mods_map("games", "off");

	const char *res = look_up_in_mods_map("systemd");
	ck_assert_str_eq("base", res);

	res = look_up_in_mods_map("games");
	ck_assert_str_eq("off", res);

	res = look_up_in_mods_map("foo");
	ck_assert_ptr_null(res);

	free_all_maps();

}
END_TEST

START_TEST (test_insert_decl_into_template_map) {

	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_t");
	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_exec_t");
	insert_decl_into_template_map("user_domain", DECL_ROLE, "$1_r");

	insert_decl_into_template_map("other_template", DECL_TYPE, "$1_conf_t");

	const struct decl_list *dl = look_up_decl_in_template_map("doesntexist");
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
	call->args = calloc(1, sizeof(struct string_list));
	call->args->string = strdup("bar_t");
	call->args->next = NULL;

	insert_call_into_template_map("user_domain", call);

	insert_decl_into_template_map("user_domain", DECL_TYPE, "$1_conf_t");

	const struct if_call_list *out = look_up_call_in_template_map("user_domain");

	ck_assert_ptr_eq(call, out->call);

	free_if_call_data(call);

}
END_TEST

static size_t test_permmacro_map_count = 0;

static void test_permmacro_map_visitor(const char *key, const struct string_list *val)
{

	test_permmacro_map_count += strlen(key);
	test_permmacro_map_count += strlen(val->string);

}

START_TEST (test_permmacro_map) {

	struct string_list *sl1 = sl_from_str("test");
	ck_assert_ptr_nonnull(sl1);

	struct string_list *sl2 = sl_from_strs(3, "hello", "world", "!");
	ck_assert_ptr_nonnull(sl2);

	insert_into_permmacros_map("test", sl1); // consumes sl1
	insert_into_permmacros_map("standard", sl2); // consumes sl2

	ck_assert_ptr_null(look_up_in_permmacros_map("hello"));
	ck_assert_ptr_null(look_up_in_permmacros_map("Test"));

	const struct string_list *csl = look_up_in_permmacros_map("standard");
	ck_assert_ptr_nonnull(csl);
	ck_assert_str_eq("hello", csl->string);
	ck_assert_ptr_nonnull(csl->next);
	ck_assert_str_eq("world", csl->next->string);

	visit_all_in_permmacros_map(test_permmacro_map_visitor);

	ck_assert_uint_eq(2 * strlen("test") + strlen("standard") + strlen("hello"), test_permmacro_map_count);

	free_all_maps();

}
END_TEST

static Suite *maps_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Maps");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_insert_into_type_map);
	tcase_add_test(tc_core, test_insert_into_type_map_dup);
	tcase_add_test(tc_core, test_role_and_user_maps);
	tcase_add_test(tc_core, test_class_and_perm_maps);
	tcase_add_test(tc_core, test_mods_map);
	tcase_add_test(tc_core, test_insert_decl_into_template_map);
	tcase_add_test(tc_core, test_insert_call_into_template_map);
	tcase_add_test(tc_core, test_permmacro_map);
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
