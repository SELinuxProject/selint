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

@VALGRIND_CHECK_RULES@

TESTS = check_tree check_parse_functions check_maps check_parsing check_parse_fc check_template check_file_list check_fc_checks check_check_hooks check_selint_config check_if_checks check_string_list check_runner check_startup check_te_checks check_ordering
check_PROGRAMS = ${TESTS}

EXTRA_DIST = test_utils.c

AM_CFLAGS += @CHECK_CFLAGS@
if COND_GCOV
AM_CFLAGS += --coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

TEST_UTILS_HEADS=test_utils.h $(top_builddir)/src/tree.h $(top_builddir)/src/string_list.h
TEST_UTILS_OBJS=test_utils.o $(top_builddir)/src/tree.o $(top_builddir)/src/string_list.o

UTIL_HEADS=$(top_builddir)/src/util.h
UTIL_OBJS=$(top_builddir)/src/util.o
SELINT_ERROR_HEADS=$(top_builddir)/src/selint_error.h
STRING_LIST_HEADS=$(top_builddir)/src/string_list.h
STRING_LIST_OBJS=$(top_builddir)/src/string_list.o
SELINT_CONFIG_HEADS=$(top_builddir)/src/selint_config.h ${SELINT_ERROR_HEADS} ${STRING_LIST_HEADS} ${TREE_HEADS} ${MAPS_HEADS}
SELINT_CONFIG_OBJS=$(top_builddir)/src/selint_config.o ${STRING_LIST_OBJS} ${TREE_OBJS} ${MAPS_OBJS} ${UTIL_OBJS}
TREE_HEADS=$(top_builddir)/src/tree.h ${SELINT_ERROR_HEADS} ${STRING_LIST_HEADS}
TREE_OBJS=$(top_builddir)/src/tree.o ${STRING_LIST_OBJS} $(top_builddir)/src/maps.o
FILE_LIST_HEADS=$(top_builddir)/src/file_list.h ${TREE_HEADS}
FILE_LIST_OBJS=$(top_builddir)/src/file_list.o ${TREE_OBJS}
MAPS_HEADS=$(top_builddir)/src/maps.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
MAPS_OBJS=$(top_builddir)/src/maps.o ${TREE_OBJS}
STARTUP_HEADS=$(top_builddir)/src/startup.h ${SELINT_ERROR_HEADS} ${FILE_LIST_HEADS}
STARTUP_OBJS=$(top_builddir)/src/startup.o ${FILE_LIST_OBJS}
TEMPLATE_HEADS=$(top_builddir)/src/template.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
TEMPLATE_OBJS=$(top_builddir)/src/template.o ${TREE_OBJS}
PARSE_FUNCTIONS_HEADS=$(top_builddir)/src/parse_functions.h ${SELINT_ERROR_HEADS} ${TREE_HEADS} ${MAPS_HEADS}
PARSE_FUNCTIONS_OBJS=$(top_builddir)/src/parse_functions.o ${TEMPLATE_OBJS} ${ORDERING_OBJS}
PARSE_HEADS=$(top_builddir)/src/parse.h ${PARSE_FUNCTIONS_HEADS}
PARSE_OBJS=$(top_builddir)/src/parse.o $(top_builddir)/src/lex.o ${CHECK_HOOKS_OBJS} ${PARSE_FUNCTIONS_OBJS}
PARSE_FC_HEADS = $(top_builddir)/src/parse_fc.h $(TREE_HEADS)
PARSE_FC_OBJS = $(top_builddir)/src/parse_fc.o $(TREE_OBJS)
CHECK_HOOKS_HEADS=$(top_builddir)/src/check_hooks.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
CHECK_HOOKS_OBJS=$(top_builddir)/src/check_hooks.o ${TREE_OBJS}
FC_CHECKS_HEADS=$(top_builddir)/src/fc_checks.h ${CHECK_HOOKS_HEADS}
FC_CHECKS_OBJS=$(top_builddir)/src/fc_checks.o ${CHECK_HOOKS_OBJS}
IF_CHECKS_HEADS=$(top_builddir)/src/if_checks.h ${CHECK_HOOKS_HEADS}
IF_CHECKS_OBJS=$(top_builddir)/src/if_checks.o ${CHECK_HOOKS_OBJS}
TE_CHECKS_HEADS=$(top_builddir)/src/te_checks.h ${CHECK_HOOKS_HEADS}
TE_CHECKS_OBJS=$(top_builddir)/src/te_checks.o ${CHECK_HOOKS_OBJS} $(top_builddir)/src/ordering.o
RUNNER_HEADS=$(top_builddir)/src/runner.h ${SELINT_ERROR_HEADS} ${CHECK_HOOKS_HEADS} ${PARSE_FUNCTIONS_HEADS} ${FILE_LIST_HEADS}
RUNNER_OBJS=$(top_builddir)/src/runner.o ${CHECK_HOOKS_OBJS} ${PARSE_FUNCTIONS_OBJS} ${FILE_LIST_OBJS} ${FC_CHECKS_OBJS} ${IF_CHECKS_OBJS} ${TE_CHECKS_OBJS} ${PARSE_FC_OBJS} ${UTIL_OBJS} ${STARTUP_OBJS} ${PARSE_OBJS}
ORDERING_HEADS=$(top_builddir)/src/ordering.h ${SELINT_ERROR_HEADS} ${TREE_HEADS}
ORDERING_OBJS=$(top_builddir)/src/ordering.o ${TREE_OBJS} ${MAPS_OBJS}

check_string_list_SOURCES = check_string_list.c ${STRING_LIST_HEADS}
check_string_list_LDADD = @CHECK_LIBS@ $(sort ${STRING_LIST_OBJS})

check_selint_config_SOURCES = check_selint_config.c ${SELINT_CONFIG_HEADS} ${STRING_LIST_HEADS}
check_selint_config_LDADD = @CHECK_LIBS@ $(sort ${SELINT_CONFIG_OBJS} ${STRING_LIST_OBJS})

check_maps_SOURCES = check_maps.c ${MAPS_HEADS}
check_maps_LDADD = @CHECK_LIBS@ $(sort ${MAPS_OBJS})

check_startup_SOURCES = check_startup.c ${STARTUP_HEADS} ${MAPS_HEADS} ${SELINT_ERROR_HEADS}
check_startup_LDADD = @CHECK_LIBS@ $(sort ${STARTUP_OBJS} ${MAPS_OBJS})

check_tree_SOURCES = check_tree.c ${TREE_HEADS} ${TEST_UTILS_HEADS}
check_tree_LDADD = @CHECK_LIBS@ $(sort ${TREE_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS})

check_file_list_SOURCES = check_file_list.c ${FILE_LIST_HEADS}
check_file_list_LDADD = @CHECK_LIBS@ $(sort ${FILE_LIST_OBJS})

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADS} ${MAPS_HEADS} ${SELINT_ERROR_HEADS}
check_parse_functions_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FUNCTIONS_OBJS} ${MAPS_OBJS})

check_parsing_SOURCES = check_parsing.c ${PARSE_HEADS} ${TREE_HEADS} ${PARSE_FUNCTIONS_HEADS} ${SELINT_ERROR_HEADS}
check_parsing_LDADD = @CHECK_LIBS@ $(sort ${PARSE_OBJS} ${TREE_OBJS} ${PARSE_FUNCTIONS_OBJS})

check_parse_fc_SOURCES = check_parse_fc.c ${PARSE_FC_HEADS} ${TREE_HEADS}
check_parse_fc_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FC_OBJS} ${TREE_OBJS})

check_template_SOURCES = check_template.c ${PARSE_FUNCTIONS_HEADS} ${TEMPLATE_HEADS} ${PARSE_HEADS} ${MAPS_HEADS}
check_template_LDADD = @CHECK_LIBS@ $(sort ${PARSE_FUNCTIONS_OBJS} ${TEMPLATE_OBJS} ${PARSE_OBJS} ${MAPS_OBJS})

check_check_hooks_SOURCES = check_check_hooks.c ${CHECK_HOOKS_HEADS}
check_check_hooks_LDADD = @CHECK_LIBS@ $(sort ${CHECK_HOOKS_OBJS})

check_fc_checks_SOURCES = check_fc_checks.c ${FC_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS}
check_fc_checks_LDADD = @CHECK_LIBS@ $(sort ${FC_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS})

check_if_checks_SOURCES = check_if_checks.c ${IF_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS} ${TEST_UTILS_HEADS}
check_if_checks_LDADD = @CHECK_LIBS@ $(sort ${IF_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS})

check_te_checks_SOURCES = check_te_checks.c ${TE_CHECKS_HEADS} ${CHECK_HOOKS_HEADS} ${MAPS_HEADS} ${TEST_UTILS_HEADS}
check_te_checks_LDADD = @CHECK_LIBS@ $(sort ${TE_CHECKS_OBJS} ${CHECK_HOOKS_OBJS} ${MAPS_OBJS} ${TEST_UTILS_OBJS})

check_runner_SOURCES = check_runner.c ${STRING_LIST_HEADS} ${RUNNER_HEADS}
check_runner_LDADD = @CHECK_LIBS@ $(sort ${STRING_LIST_OBJS} ${RUNNER_OBJS})

check_ordering_SOURCES = check_ordering.c ${ORDERING_HEADS} ${RUNNER_HEADS} ${MAPS_HEADS}
check_ordering_LDADD = @CHECK_LIBS@ $(sort ${ORDERING_OBJS} ${RUNNER_OBJS} ${MAPS_OBJS})

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
