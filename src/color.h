/*
* Copyright 2020 The SELint Contributors
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

#ifndef COLOR_H
#define COLOR_H

/*********************************************
* Enable colored output.
* All color functions only return color control sequences, if colored output has been enabled.
* Prior to that all color functions return an empty string.
*********************************************/
void color_enable(void);

/*********************************************
* Reset any previous color setting.
* Should be used after any marking color function.
*********************************************/
const char *color_reset(void);

/*********************************************
* Mark the following output with an error color.
*********************************************/
const char *color_error(void);

/*********************************************
* Mark the following output with a warning color.
*********************************************/
const char *color_warning(void);

/*********************************************
* Mark the following output with a note color.
*********************************************/
const char *color_note(void);

/*********************************************
* Mark the following output with an ok color.
*********************************************/
const char *color_ok(void);

/*********************************************
* Mark the following output with the appropriate color for the given severity.
* severity - The severity to decide the color.
*********************************************/
const char *color_severity(char severity);

#endif /* COLOR_H */
