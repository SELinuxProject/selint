bin_PROGRAMS = selint
selint_SOURCES = main.c lex.l parse.y tree.c tree.h selint_error.h parse_functions.c parse_functions.h maps.c maps.h runner.c runner.h parse_fc.c parse_fc.h template.c template.h file_list.c file_list.h check_hooks.c check_hooks.h fc_checks.c fc_checks.h util.c util.h if_checks.c if_checks.h selint_config.c selint_config.h
BUILT_SOURCES = parse.h
AM_YFLAGS = -d

if COND_GCOV
MAYBE_COVERAGE=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

AM_CFLAGS = $(MAYBE_COVERAGE) -Wall

MOSTLYCLEANFILES = *.gcda *.gcno *.gcov
