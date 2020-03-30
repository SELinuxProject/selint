/*
* Copyright 2020 Tresys Technology, LLC
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

#include "color.h"

static int enabled = 0;

#define COLOR_RESET    "\033[0m"
#define COLOR_BOLD     "\033[1m"
#define COLOR_RED      "\033[31;1m"
#define COLOR_GREEN    "\033[32;1m"
#define COLOR_YELLOW   "\033[33;1m"
#define COLOR_BLUE     "\033[34;1m"
#define COLOR_MAGENTA  "\033[35;1m"
#define COLOR_CYAN     "\033[36;1m"
#define EMPTY_STR      ""

void color_enable()
{
	enabled = 1;
}

const char *color_reset()
{
	if (!enabled) {
		return EMPTY_STR;
	}

	return COLOR_RESET;
}

const char *color_error()
{
	if (!enabled) {
		return EMPTY_STR;
	}

	return COLOR_RED;
}

const char *color_warning()
{
	if (!enabled) {
		return EMPTY_STR;
	}

	return COLOR_YELLOW;
}

const char *color_note()
{
	if (!enabled) {
		return EMPTY_STR;
	}

	return COLOR_MAGENTA;
}

const char *color_ok()
{
	if (!enabled) {
		return EMPTY_STR;
	}

	return COLOR_GREEN;
}

const char *color_severity(char severity)
{
	if (!enabled) {
		return EMPTY_STR;
	}

	switch (severity) {
	case 'E':
		return COLOR_RED;
	case 'W':
		return COLOR_YELLOW;
	case 'S':
		return COLOR_MAGENTA;
	case 'C':
		return COLOR_BLUE;
	}

	return COLOR_BOLD;
}
