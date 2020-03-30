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

bin_PROGRAMS = selint
selint_SOURCES = main.c lex.l parse.y tree.c tree.h selint_error.h parse_functions.c parse_functions.h maps.c maps.h runner.c runner.h parse_fc.c parse_fc.h template.c template.h file_list.c file_list.h check_hooks.c check_hooks.h fc_checks.c fc_checks.h util.c util.h if_checks.c if_checks.h selint_config.c selint_config.h string_list.c string_list.h startup.c startup.h te_checks.c te_checks.h ordering.c ordering.h color.c color.h
BUILT_SOURCES = parse.h
AM_YFLAGS = -d -Wno-yacc -Werror=conflicts-rr -Werror=conflicts-sr

if COND_GCOV
MAYBE_COVERAGE=--coverage -fno-inline -fno-inline-small-functions -fno-default-inline
endif

AM_CFLAGS += $(MAYBE_COVERAGE) -DSYSCONFDIR='"$(sysconfdir)"'

MOSTLYCLEANFILES = *.gcda *.gcno *.gcov lex.c parse.c parse.h
