TESTS = check_tree check_parse_functions
check_PROGRAMS = check_tree check_parse_functions

if COND_GCOV
EXTRA_CFLAGS=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

TREE_HEADER=$(top_builddir)/src/tree.h
TREE_OBJ=$(top_builddir)/src/tree.o
PARSE_FUNCTIONS_HEADER=$(top_builddir)/src/parse_functions.h
PARSE_FUNCTIONS_OBJ=$(top_builddir)/src/parse_functions.o

check_tree_SOURCES = check_tree.c ${TREE_HEADER} $(top_buildddir)/src/selint_error.h
check_tree_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_tree_LDADD = @CHECK_LIBS@ ${TREE_OBJ}

check_parse_functions_SOURCES = check_parse_functions.c ${PARSE_FUNCTIONS_HEADER} ${TREE_HEADER} $(top_buildddir)/src/selint_error.h
check_parse_functions_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_functions_LDADD = @CHECK_LIBS@ ${PARSE_FUNCTIONS_OBJ} ${TREE_OBJ}

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
