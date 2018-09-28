#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(selint, 0.1, dburgener@tresys.com)
AC_CONFIG_SRCDIR([src/selint_main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(selint, 0.1)

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC

# Checks for libraries.

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h libintl.h malloc.h stddef.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strdup])

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT(Makefile src/Makefile)
