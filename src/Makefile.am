bin_PROGRAMS = selint
selint_SOURCES = main.c lex.l parse.y tree.c tree.h selint_error.h parse_functions.c parse_functions.h maps.c maps.h
BUILT_SOURCES = parse.h
AM_YFLAGS = -d

if COND_GCOV
MAYBE_COVERAGE=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

AM_CFLAGS = $(MAYBE_COVERAGE) -Wall

MOSTLYCLEANFILES = *.gcda *.gcno *.gcov
