#!/usr/bin/env/bats

# Copyright 2019 Tresys Technology, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SELINT_PATH=../../src/selint

do_test() {
	local CHECK_ID=$1
	local FILENAME=$2
	local EXPECT=$3
	local ARGS=$4
	run ${SELINT_PATH} -s -c tmp.conf ${ARGS} ./policies/check_triggers/${FILENAME} ./policies/check_triggers/modules.conf
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o ${CHECK_ID} | wc -l)
	echo "Status: $status, Count: $count (expected ${EXPECT})"
	echo $output
	[ "$count" -eq ${EXPECT} ]
}

test_one_check_expect() {
	local CHECK_ID=$1
	local FILENAME=$2
	local EXPECT=$3

	echo "disable = { $CHECK_ID } " > tmp.conf
	do_test ${CHECK_ID} ${FILENAME} 0

	echo "enable_source = { $CHECK_ID }" >> tmp.conf
	do_test ${CHECK_ID} ${FILENAME} ${EXPECT}

	do_test ${CHECK_ID} ${FILENAME} 0 "-d $CHECK_ID"

	do_test ${CHECK_ID} ${FILENAME} ${EXPECT} "-e $CHECK_ID"

	do_test ${CHECK_ID} ${FILENAME} ${EXPECT} "-e $CHECK_ID -d $CHECK_ID"

	rm tmp.conf
}

test_ordering() {
	local CHECK_DIR="./policies/check_triggers/C-001/"
	local FILENAME_PREFIX=$1
	run ${SELINT_PATH} -rs -c configs/default.conf -e C-001 -E ${CHECK_DIR}${FILENAME_PREFIX}.te ${CHECK_DIR}interfaces ./policies/check_triggers/modules.conf
	echo ${output}
	while read p; do
		echo "Checking for $p"
		count=$(echo ${output} | grep -o ${p} | wc -l)
		[ "$count" -eq "1" ]
	done < "${CHECK_DIR}/${FILENAME_PREFIX}.expect"
	local EXPECT_COUNT=$(cat ${CHECK_DIR}/${FILENAME_PREFIX}.expect | wc -l)
	count=$(echo ${output} | grep -o C-001 | wc -l)
	echo "Expecting: ${EXPECT_COUNT}, got: $count"
	[ "$count" -eq "${EXPECT_COUNT}" ]
}

test_one_check() {
	test_one_check_expect $1 $2 1
}

@test "C-001" {
	test_ordering "simple"
	test_ordering "interleaved"
	test_ordering "optional"
	test_ordering "role_ifs"
	test_ordering "types_in_requires"
	test_ordering "kernel_module_first"
}

@test "C-004" {
	test_one_check "C-004" "c04.if"
}

@test "S-001" {
	test_one_check "S-001" "s01.te"
}

@test "S-002" {
	test_one_check "S-002" "s02*"
}

@test "W-001" {
	test_one_check "W-001" "w01*"
}

@test "W-002" {
	test_one_check "W-002" "w02.*"
	test_one_check "W-002" "w02_role.*"
}

@test "W-003" {
	test_one_check "W-003" "w03.if"
	test_one_check "W-003" "w03_role.if"
	test_one_check_expect "W-003" "w03_ta.if" 0
	test_one_check_expect "W-003" "w03_alias.if" 0
}

@test "W-004" {
	test_one_check "W-004" "w04.fc"
}

@test "W-005" {
	test_one_check "W-005" "w05*"
}

@test "E-002" {
	test_one_check "E-002" "e02.fc"
}

@test "E-003" {
	test_one_check "E-003" "e03e04e05.fc"
}

@test "E-004" {
	test_one_check "E-004" "e03e04e05.fc"
}

@test "E-005" {
	test_one_check "E-005" "e03e04e05.fc"
}

@test "assume_user" {
	do_test "E-003" "e03e04e05.fc" 1 "-e E-003"
	echo "assume_users = { system_u }" >> tmp.conf
	do_test "E-003" "e03e04e05.fc" 0 "-e E-003"
	rm tmp.conf
}

@test "assume_role" {
	do_test "E-004" "e03e04e05.fc" 1 "-e E-004"
	echo "assume_roles = { object_r }" >> tmp.conf
	do_test "E-004" "e03e04e05.fc" 0 "-e E-004"
	rm tmp.conf
}

@test "usage" {
	run ${SELINT_PATH}
	[ "$status" -eq 64 ]
	usage_presence=$(echo ${output} | grep -o "^Usage" | wc -l)
	[ "$usage_presence" -eq 1 ]

	run ${SELINT_PATH} -Z
	[ "$status" -eq 64 ]
	usage_presence=$(echo ${output} | grep -o "Usage" | wc -l)
	[ "$usage_presence" -eq 1 ]
	message_presence=$(echo ${output} | grep -o "invalid option -- 'Z'" | wc -l)
	[ "$message_presence" -eq 1 ]
}

@test "Enable/disable" {
	run ${SELINT_PATH} -c configs/empty.conf -e W-002 -e W-003 -d S-002 -d C-002 -r -s policies/check_triggers
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "S-002" | wc -l)
	[ "$count" -eq 0 ]
	count=$(echo ${output} | grep -o "C-002" | wc -l)
	[ "$count" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	[ "$count" -gt 0 ]
	count=$(echo ${output} | grep -o "W-003" | wc -l)
	[ "$count" -gt 0 ]
}

@test "verbose mode" {
	run ${SELINT_PATH} -c configs/default.conf -r -s -v policies/check_triggers
	[ "$status" -eq 0 ]
	verbose_presence=$(echo ${output} | grep -o "^Verbose" | wc -l)
	[ "$verbose_presence" -eq 1 ]
}

@test "valgrind" {
	run valgrind --leak-check=full --error-exitcode=1 ${SELINT_PATH} -c configs/default.conf -r -s policies/check_triggers
	[ "$status" -eq 0 ]
}

@test "nesting_gen_req" {
	run ${SELINT_PATH} -c configs/default.conf -e W-002 -E -s policies/misc/nesting.*
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	echo "Status: $status, Count: $count (expected 1)"
	echo $output
	[ "$count" -eq 1 ]
	count=$(echo ${output} | grep -o "foo_data_t" | wc -l)
	echo "Status: $status, Count: $count (expected 1)"
	echo $output
	[ "$count" -eq 1 ]
	count=$(echo ${output} | grep -o "foo_log_t" | wc -l)
	echo "Status: $status, Count: $count (expected 0)"
	echo $output
	[ "$count" -eq 0 ]
}

@test "disable comment" {
	run ${SELINT_PATH} -c configs/default.conf -e W-002 -E -s policies/misc/disable.*
	[ "$status" -eq 0 ]
	count=$(echo ${output} | grep -o "W-002" | wc -l)
	echo "Status: $status, Count: $count (expected 0)"
	echo $output
	[ "$count" -eq 0 ]

	run ${SELINT_PATH} -c configs/default.conf policies/misc/disable_multiple*
	[ "$status" -eq 0 ]
	[ "$output" == "" ]

	run ${SELINT_PATH} -c configs/default.conf policies/misc/disable_require_start.*
	[ "$status" -eq 0 ]
	[ "$output" == "" ]
}

@test "nonexistent file" {
	run ${SELINT_PATH} -c configs/default.conf doesnt_exist.te
	[ "$status" -eq 70 ]
	run ${SELINT_PATH} -c configs/default.conf doesnt_exist.if
	[ "$status" -eq 70 ]
	run ${SELINT_PATH} -c configs/default.conf doesnt_exist.fc
	[ "$status" -eq 70 ]
}

@test "Broken config" {
	run valgrind --leak-check=full --error-exitcode=1 ${SELINT_PATH} -c configs/broken.conf -rs policies/check_triggers
	[ "$status" -eq 78 ]
}

@test "Bad check ids" {
	run ${SELINT_PATH} -c configs/default.conf policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning" | wc -l)
	[ "$count" -eq 0 ]

	run ${SELINT_PATH} -c configs/default.conf -e foo policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning" | wc -l)
	[ "$count" -eq 1 ]

	run ${SELINT_PATH} -c configs/default.conf -d foo policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning" | wc -l)
	[ "$count" -eq 1 ]

	run ${SELINT_PATH} -c configs/bad_ids.conf policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning" | wc -l)
	[ "$count" -eq 2 ]

	run ${SELINT_PATH} -c configs/bad_ids.conf -e foo -d bar -d baz policies/misc/no_issues.te
	count=$(echo ${output} | grep -o "Warning" | wc -l)
	[ "$count" -eq 5 ]
}
