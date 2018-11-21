TESTS = check_tree check_parse_functions
check_PROGRAMS = check_tree check_parse_functions

if COND_GCOV
EXTRA_CFLAGS=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

MAPS_HEADS=$(top_builddir)/src/maps.h
MAPS_OBJS=$(top_builddir)/src/maps.o
TREE_HEADS=$(top_builddir)/src/tree.h
TREE_OBJS=$(top_builddir)/src/tree.o
PARSE_FUNCTIONS_HEADS=$(top_builddir)/src/parse_functions.h ${TREE_HEADS} ${MAPS_HEADS}
PARSE_FUNCTIONS_OBJS=$(top_builddir)/src/parse_functions.o ${TREE_OBJS} ${MAPS_OBJS}

check_maps_SOURCES = check_maps.c ${MAPS_HEADS}
check_maps_CFLAGS = @CHECK_CFLAGS ${EXTRA_CFLAGS}
check_maps_LDADD = @CHECK_LIBS@ ${MAPS_OBJS}

check_tree_SOURCES = check_tree.c ${TREE_HEADS} $(top_buildddir)/src/selint_error.h
check_tree_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_tree_LDADD = @CHECK_LIBS@ ${TREE_OBJS}

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADS} $(top_buildddir)/src/selint_error.h
check_parse_functions_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_functions_LDADD = @CHECK_LIBS@ ${PARSE_FUNCTIONS_OBJS}

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
