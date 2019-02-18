TESTS = check_tree check_parse_functions check_maps check_parsing check_parse_fc check_template check_file_list check_fc_checks check_check_hooks check_selint_config check_if_checks check_string_list check_runner
check_PROGRAMS = ${TESTS}

if COND_GCOV
EXTRA_CFLAGS=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

UTIL_HEADS=$(top_builddir)/src/util.h
UTIL_OBJS=$(top_builddir)/src/util.o
STRING_LIST_HEADS=$(top_builddir)/src/string_list.h
STRING_LIST_OBJS=$(top_builddir)/src/string_list.o
SELINT_CONFIG_HEADS=$(top_builddir)/src/selint_config.h ${UTIL_HEADS} ${STRING_LIST_HEADS}
SELINT_CONFIG_OBJS=$(top_builddir)/src/selint_config.o ${UTIL_OBJS} ${STRING_LIST_OBJS}
TREE_HEADS=$(top_builddir)/src/tree.h $(top_builddir)/src/string_list.h
TREE_OBJS=$(top_builddir)/src/tree.o $(top_builddir)/src/maps.o $(top_builddir)/src/string_list.o
FILE_LIST_HEADS=$(top_builddir)/src/file_list.h ${TREE_HEADS}
FILE_LIST_OBJS=$(top_builddir)/src/file_list.o ${TREE_OBJS}
MAPS_HEADS=$(top_builddir)/src/maps.h ${TREE_HEADS}
MAPS_OBJS=${TREE_OBJS}
TEMPLATE_HEADS=$(top_builddir)/src/template.h ${MAPS_HEADS}
TEMPLATE_OBJS=$(top_builddir)/src/template.o ${MAPS_OBJS}
PARSE_FUNCTIONS_HEADS=$(top_builddir)/src/parse_functions.h ${TEMPLATE_HEADS}
PARSE_FUNCTIONS_OBJS=$(top_builddir)/src/parse_functions.o ${TEMPLATE_OBJS}
PARSING_HEADS=$(top_builddir)/src/parse.h ${PARSE_FUNCTIONS_HEADS} ${CHECK_HOOKS_HEADS}
PARSING_OBJS=$(top_builddir)/src/parse.o $(top_builddir)/src/lex.o ${PARSE_FUNCTIONS_OBJS} $(top_builddir)/src/check_hooks.o
PARSE_FC_HEADS = $(top_builddir)/src/parse_fc.h $(TREE_HEADS)
PARSE_FC_OBJS = $(top_builddir)/src/parse_fc.o $(TREE_OBJS)
CHECK_HOOKS_HEADS=$(top_builddir)/src/check_hooks.h ${TREE_HEADS}
CHECK_HOOKS_OBJS=$(top_builddir)/src/check_hooks.o ${TREE_OBJS}
FC_CHECKS_HEADS=$(top_builddir)/src/fc_checks.h ${CHECK_HOOKS_HEADS}
FC_CHECKS_OBJS=$(top_builddir)/src/fc_checks.o ${CHECK_HOOKS_OBJS}
IF_CHECKS_HEADS=$(top_builddir)/src/if_checks.h ${CHECK_HOOKS_HEADS}
IF_CHECKS_OBJS=$(top_builddir)/src/if_checks.o ${CHECK_HOOKS_OBJS}
RUNNER_HEADS=$(top_builddir)/src/runner.h ${PARSING_HEADS} ${UTIL_HEADS} $(top_builddir)/src/parse_fc.h $(top_builddir)/src/*_checks.h
RUNNER_OBJS=$(top_builddir)/src/runner.o ${PARSING_OBJS} ${UTIL_OBJS} $(top_builddir)/src/parse_fc.o $(top_builddir)/src/*_checks.o

check_string_list_SOURCES = check_string_list.c ${STRING_LIST_HEADS}
check_string_list_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_string_list_LDADD = @CHECK_LIBS@ ${STRING_LIST_OBJS}

check_selint_config_SOURCES = check_selint_config.c ${SELINT_CONFIG_HEADS}
check_selint_config_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_selint_config_LDADD = @CHECK_LIBS@ ${SELINT_CONFIG_OBJS}

check_maps_SOURCES = check_maps.c ${MAPS_HEADS}
check_maps_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_maps_LDADD = @CHECK_LIBS@ ${MAPS_OBJS}

check_tree_SOURCES = check_tree.c ${TREE_HEADS} $(top_builddir)/src/selint_error.h
check_tree_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_tree_LDADD = @CHECK_LIBS@ ${TREE_OBJS}

check_file_list_SOURCES = check_file_list.c ${FILE_LIST_HEADS}
check_file_list_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_file_list_LDADD = @CHECK_LIBS@ ${FILE_LIST_OBJS}

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADS} $(top_builddir)/src/selint_error.h
check_parse_functions_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_functions_LDADD = @CHECK_LIBS@ ${PARSE_FUNCTIONS_OBJS}

check_parsing_SOURCES = check_parsing.c ${PARSING_HEADS} $(top_builddir)/src/selint_error.h
check_parsing_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parsing_LDADD = @CHECK_LIBS@ ${PARSING_OBJS}

check_parse_fc_SOURCES = check_parse_fc.c ${PARSE_FC_HEADS}
check_parse_fc_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_fc_LDADD = @CHECK_LIBS@ ${PARSE_FC_OBJS}

check_template_SOURCES = check_template.c ${PARSING_HEADS}
check_template_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_template_LDADD = @CHECK_LIBS@ ${PARSING_OBJS}

check_check_hooks_SOURCES = check_check_hooks.c ${CHECK_HOOKS_HEADS}
check_check_hooks_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_check_hooks_LDADD = @CHECK_LIBS@ ${CHECK_HOOKS_OBJS}

check_fc_checks_SOURCES = check_fc_checks.c ${FC_CHECKS_HEADS}
check_fc_checks_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_fc_checks_LDADD = @CHECK_LIBS@ ${FC_CHECKS_OBJS}

check_if_checks_SOURCES = check_if_checks.c ${IF_CHECKS_HEADS}
check_if_checks_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_if_checks_LDADD = @CHECK_LIBS@ ${IF_CHECKS_OBJS}

check_runner_SOURCES = check_runner.c ${RUNNER_HEADS}
check_runner_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_runner_LDADD = @CHECK_LIBS@ ${RUNNER_OBJS}

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
