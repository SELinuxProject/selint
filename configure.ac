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

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([selint], [1.3.0], [Daniel.Burgener@microsoft.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_LEX
AC_PROG_YACC

# Check for testsuite Check library
AC_ARG_WITH([check],
        [AS_HELP_STRING([--without-check],
                [Build without testsuite depending on Check (default: Build with testsuite)])],
                [with_check=${withval}],
                [with_check=yes])
AM_CONDITIONAL([WITH_CHECK], [test "x$with_check" = "xyes"])
AS_IF([test "x$with_check" = "xyes"], [PKG_CHECK_MODULES([CHECK], [check >= 0.11.0], [], [AC_MSG_ERROR([Check not found])])])

# Checks for libraries.
AC_SEARCH_LIBS([cfg_init], [confuse], [], [
  AC_MSG_ERROR([Unable to find libconfuse])
])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h libintl.h malloc.h stddef.h stdlib.h string.h unistd.h stdbool.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strdup])

AC_ARG_ENABLE([gcov],
  [AS_HELP_STRING([--enable-gcov],
    [use Gcov to test the test suite])],
    [enable_gcov=${enableval}],
    [])

AM_CONDITIONAL([COND_GCOV],[ test "x$enable_gcov" "=" "xyes" ])

AC_CHECK_PROGS([HELP2MAN], [help2man])
if ! test -z "$HELP2MAN"
then
AC_SUBST(MANPAGES, selint.1)
HAVE_HELP2MAN=true
fi
AM_CONDITIONAL([HAVE_HELP2MAN], [test "x$HAVE_HELP2MAN" "=" "xtrue"])

AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

AC_CHECK_HEADER([uthash.h], [], [AC_MSG_ERROR([Unable to find uthash header])])

AM_CFLAGS="-Wall -Wextra -Wcast-qual -Wconversion -Wmissing-format-attribute -Wmissing-noreturn -Wmissing-prototypes -Wpointer-arith -Wshadow -Wstrict-prototypes -Wundef -Wunused -Wwrite-strings"
AC_ARG_ENABLE([werror],
  [AS_HELP_STRING([--enable-werror],
    [Treat compiler warnings as errors (default: Do not treat as errors)])],
    [AM_CFLAGS+=" -Werror"])
AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile man/Makefile])
AC_OUTPUT()
