TESTS = check_tree check_parse_functions check_maps check_parsing
check_PROGRAMS = check_tree check_parse_functions check_maps check_parsing

if COND_GCOV
EXTRA_CFLAGS=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

TREE_HEADS=$(top_builddir)/src/tree.h
TREE_OBJS=$(top_builddir)/src/tree.o
MAPS_HEADS=$(top_builddir)/src/maps.h ${TREE_HEADS}
MAPS_OBJS=$(top_builddir)/src/maps.o ${TREE_OBJS}
PARSE_FUNCTIONS_HEADS=$(top_builddir)/src/parse_functions.h ${MAPS_HEADS}
PARSE_FUNCTIONS_OBJS=$(top_builddir)/src/parse_functions.o ${MAPS_OBJS}
PARSING_HEADS=$(top_builddir)/src/parse.h ${PARSE_FUNCTIONS_HEADS}
PARSING_OBJS=$(top_builddir)/src/parse.o $(top_builddir)/src/lex.o ${PARSE_FUNCTIONS_OBJS}

check_maps_SOURCES = check_maps.c ${MAPS_HEADS}
check_maps_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_maps_LDADD = @CHECK_LIBS@ ${MAPS_OBJS}

check_tree_SOURCES = check_tree.c ${TREE_HEADS} $(top_buildddir)/src/selint_error.h
check_tree_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_tree_LDADD = @CHECK_LIBS@ ${TREE_OBJS}

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADS} $(top_buildddir)/src/selint_error.h
check_parse_functions_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_functions_LDADD = @CHECK_LIBS@ ${PARSE_FUNCTIONS_OBJS}

check_parsing_SOURCES = check_parsing.c ${PARSING_HEADS} $(top_builddir)/src/selint_error.h
check_parsing_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parsing_LDADD = @CHECK_LIBS@ ${PARSING_OBJS}

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
