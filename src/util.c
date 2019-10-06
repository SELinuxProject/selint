#include <stdio.h>
#include <stdarg.h>

#include "util.h"

int verbose_flag;

void print_if_verbose(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	if (verbose_flag) {
		vprintf(format, args);
	}
	va_end(args);
}
