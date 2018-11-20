TESTS = check_tree check_parse_functions
check_PROGRAMS = check_tree check_parse_functions

if COND_GCOV
EXTRA_CFLAGS=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

check_tree_SOURCES = check_tree.c $(top_builddir)/src/tree.h $(top_buildddir)/src/selint_error.h
check_tree_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_tree_LDADD = @CHECK_LIBS@ $(top_builddir)/src/tree.o

check_parse_functions_SOURCES = check_parse_functions.c $(top_builddir)/src/check_parse_functions.h $(top_builddir)/src/tree.h $(top_buildddir)/src/selint_error.h
check_parse_functions_CFLAGS = @CHECK_CFLAGS@ ${EXTRA_CFLAGS}
check_parse_functions_LDADD = @CHECK_LIBS@ $(top_builddir)/src/parse_functions.o

MOSTLYCLEANFILES = *.gcov *.gcda *.gcno
