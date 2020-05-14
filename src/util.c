/*
* Copyright 2019 Tresys Technology, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "util.h"

int verbose_flag;

void print_if_verbose(const char *format, ...)
{
	if (!verbose_flag) {
		return;
	}

	va_list args;

	va_start(args, format);

	vprintf(format, args);

	va_end(args);
}

bool ends_with(const char *str, size_t str_len, const char *suffix, size_t suffix_len)
{
	if (str_len < suffix_len) {
		return 0;
	}

	return (0 == strncmp(str + str_len - suffix_len, suffix, suffix_len));
}

char* trim_right(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && isspace((unsigned char)str[len-1])) {
		str[len-1] = '\0';
		len--;
	}

	return str;
}
