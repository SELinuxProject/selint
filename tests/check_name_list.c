/*
 * Copyright 2022 The SELint Contributors
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
#include <stdlib.h>

#include "../src/name_list.h"
#include "../src/tree.h"

START_TEST (test_name_list_create) {

	struct name_list *nl = name_list_create("foo", NAME_ROLEATTRIBUTE);

	ck_assert_ptr_nonnull(nl);
	ck_assert_ptr_nonnull(nl->data);
	ck_assert_str_eq("foo", nl->data->name);
	ck_assert_int_eq(NAME_ROLEATTRIBUTE, nl->data->flavor);
	ck_assert_ptr_null(nl->data->traits);
	ck_assert_ptr_null(nl->next);

	free_name_list(nl);

}
END_TEST

START_TEST (test_name_list_from_sl) {

	struct string_list *sl, *traits;
	struct name_list *nl;

	sl = NULL;
	nl = name_list_from_sl_with_traits(sl, NAME_TYPE, NULL);
	ck_assert_ptr_null(nl);

	sl = sl_from_strs(2, "foo", "bar");
	nl = name_list_from_sl_with_traits(sl, NAME_TYPE, NULL);

	ck_assert_ptr_nonnull(nl);
	ck_assert_ptr_nonnull(nl->data);
	ck_assert_str_eq("foo", nl->data->name);
	ck_assert_int_eq(NAME_TYPE, nl->data->flavor);
	ck_assert_ptr_null(nl->data->traits);

	ck_assert_ptr_nonnull(nl->next);
	ck_assert_str_eq("bar", nl->next->data->name);
	ck_assert_int_eq(NAME_TYPE, nl->next->data->flavor);
	ck_assert_ptr_null(nl->next->data->traits);
	ck_assert_ptr_null(nl->next->next);

	free_name_list(nl);
	free_string_list(sl);

	sl = sl_from_strs(3, "foo", "bar", "baz");
	traits = sl_from_strs(2, "alpha", "beta");
	nl = name_list_from_sl_with_traits(sl, NAME_ROLE, traits);

	ck_assert_ptr_nonnull(nl);
	ck_assert_ptr_nonnull(nl->data);
	ck_assert_str_eq("foo", nl->data->name);
	ck_assert_int_eq(NAME_ROLE, nl->data->flavor);
	ck_assert_ptr_nonnull(nl->data->traits);
	ck_assert_str_eq("alpha", nl->data->traits->string);
	ck_assert_str_eq("beta", nl->data->traits->next->string);
	ck_assert_ptr_null(nl->data->traits->next->next);

	ck_assert_ptr_nonnull(nl->next);
	ck_assert_ptr_nonnull(nl->next->data);
	ck_assert_str_eq("bar", nl->next->data->name);
	ck_assert_int_eq(NAME_ROLE, nl->next->data->flavor);
	ck_assert_ptr_nonnull(nl->next->data->traits);
	ck_assert_str_eq("alpha", nl->next->data->traits->string);
	ck_assert_str_eq("beta", nl->next->data->traits->next->string);
	ck_assert_ptr_null(nl->next->data->traits->next->next);

	ck_assert_ptr_nonnull(nl->next->next);
	ck_assert_ptr_nonnull(nl->next->next->data);
	ck_assert_str_eq("baz", nl->next->next->data->name);
	ck_assert_int_eq(NAME_ROLE, nl->next->next->data->flavor);
	ck_assert_ptr_nonnull(nl->next->next->data->traits);
	ck_assert_str_eq("alpha", nl->next->next->data->traits->string);
	ck_assert_str_eq("beta", nl->next->next->data->traits->next->string);
	ck_assert_ptr_null(nl->next->next->data->traits->next->next);

	ck_assert_ptr_null(nl->next->next->next);

	free_name_list(nl);
	free_string_list(traits);
	free_string_list(sl);

}
END_TEST

START_TEST (test_concat_name_lists) {

	struct name_list *res, *nl1, *nl2;

	ck_assert_ptr_null(concat_name_lists(NULL, NULL));

	nl1 = name_list_create("hello", NAME_TYPEATTRIBUTE);
	ck_assert_ptr_nonnull(nl1);

	nl2 = name_list_create("world", NAME_CLASS);
	ck_assert_ptr_nonnull(nl2);

	res = concat_name_lists(NULL, nl1);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->data->name);
	ck_assert_int_eq(NAME_TYPEATTRIBUTE, res->data->flavor);
	ck_assert_ptr_null(res->next);

	res = concat_name_lists(nl1, NULL);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->data->name);
	ck_assert_int_eq(NAME_TYPEATTRIBUTE, res->data->flavor);
	ck_assert_ptr_null(res->next);

	res = concat_name_lists(nl1, nl2);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->data->name);
	ck_assert_int_eq(NAME_TYPEATTRIBUTE, res->data->flavor);
	ck_assert_ptr_nonnull(res->next);
	ck_assert_str_eq("world", res->next->data->name);
	ck_assert_int_eq(NAME_CLASS, res->next->data->flavor);
	ck_assert_ptr_null(res->next->next);

	free_name_list(res); // frees nl1 and nl2

}
END_TEST

START_TEST (test_name_lists_from_type_decl) {

	struct declaration_data *decl = malloc(sizeof(struct declaration_data));
	decl->flavor = DECL_TYPE;
	decl->name = strdup("foo");
	decl->attrs = sl_from_strs(2, "alpha", "beta");

	struct name_list *nl = name_list_from_decl(decl);

	free_string_list(decl->attrs);
	free(decl->name);
	free(decl);

	ck_assert_ptr_nonnull(nl);
	ck_assert_ptr_nonnull(nl->data);
	ck_assert_str_eq("foo", nl->data->name);
	ck_assert_int_eq(NAME_TYPE, nl->data->flavor);
	ck_assert_ptr_null(nl->data->traits);

	ck_assert_ptr_nonnull(nl->next);
	ck_assert_ptr_nonnull(nl->next->data);
	ck_assert_str_eq("alpha", nl->next->data->name);
	ck_assert_int_eq(NAME_TYPEATTRIBUTE, nl->next->data->flavor);
	ck_assert_ptr_null(nl->next->data->traits);

	ck_assert_ptr_nonnull(nl->next->next);
	ck_assert_ptr_nonnull(nl->next->next->data);
	ck_assert_str_eq("beta", nl->next->next->data->name);
	ck_assert_int_eq(NAME_TYPEATTRIBUTE, nl->next->next->data->flavor);
	ck_assert_ptr_null(nl->next->next->data->traits);

	ck_assert_ptr_null(nl->next->next->next);

	free_name_list(nl);

}
END_TEST

START_TEST (test_name_lists_from_class_decl) {

	struct declaration_data *decl = malloc(sizeof(struct declaration_data));
	decl->flavor = DECL_CLASS;
	decl->name = strdup("foo");
	decl->attrs = sl_from_strs(2, "alpha", "beta");

	struct name_list *nl = name_list_from_decl(decl);

	free_string_list(decl->attrs);
	free(decl->name);
	free(decl);

	ck_assert_ptr_nonnull(nl);
	ck_assert_ptr_nonnull(nl->data);
	ck_assert_str_eq("foo", nl->data->name);
	ck_assert_int_eq(NAME_CLASS, nl->data->flavor);
	ck_assert_ptr_nonnull(nl->data->traits);
	ck_assert_str_eq("alpha", nl->data->traits->string);
	ck_assert_str_eq("beta", nl->data->traits->next->string);
	ck_assert_ptr_null(nl->data->traits->next->next);

	ck_assert_ptr_null(nl->next);

	free_name_list(nl);

}
END_TEST

START_TEST (test_name_list_contains) {

	struct name_list *d;
	struct name_list *nl = concat_name_lists(
		name_list_create("foo", NAME_TYPEATTRIBUTE),
		name_list_create("bar", NAME_ROLE));

	ck_assert_ptr_nonnull(nl);

	d = name_list_create("foo", NAME_TYPEATTRIBUTE);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("foo", NAME_TYPE_OR_ATTRIBUTE);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("foo", NAME_UNKNOWN);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("foo", NAME_TYPE);
	ck_assert_int_eq(0, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("foo", NAME_BOOL);
	ck_assert_int_eq(0, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("bar", NAME_ROLE);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("bar", NAME_ROLE_OR_ATTRIBUTE);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("bar", NAME_UNKNOWN);
	ck_assert_int_eq(1, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("bar", NAME_ROLEATTRIBUTE);
	ck_assert_int_eq(0, name_list_contains_name(nl, d->data));
	free_name_list(d);

	d = name_list_create("bar", NAME_TYPE);
	ck_assert_int_eq(0, name_list_contains_name(nl, d->data));
	free_name_list(d);

	free_name_list(nl);

}
END_TEST

static Suite *name_list_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Name_list");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_name_list_create);
	tcase_add_test(tc_core, test_name_list_from_sl);
	tcase_add_test(tc_core, test_concat_name_lists);
	tcase_add_test(tc_core, test_name_lists_from_type_decl);
	tcase_add_test(tc_core, test_name_lists_from_class_decl);
	tcase_add_test(tc_core, test_name_list_contains);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = name_list_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
