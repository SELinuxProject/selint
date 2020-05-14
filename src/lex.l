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
%{
#include <stdio.h>
#include <string.h>
#include "tree.h"
#include "parse.h"


extern void reset_current_lines(void);

/*
 * Callback by the lexer, called prior to every matched rule's action.
 * Update the source file location accordingly.
 */
#define YY_USER_ACTION                                  \
    yylloc->first_line = yylloc->last_line = yylineno;  \
    yylloc->first_column = yycolumn;                    \
    yylloc->last_column = yycolumn + yyleng - 1;        \
    yycolumn += yyleng;

// used by parser
char* current_lines[LINES_TO_CACHE] = { NULL };
unsigned line_cache_index = 0;

// internal state for cached lines
static size_t current_lines_alloc[LINES_TO_CACHE] = { 0 };
static size_t current_line_sent = 0;
static size_t current_line_len = 0;

void reset_current_lines(void) {
    for (unsigned i = 0; i < LINES_TO_CACHE; ++i) {
        free(current_lines[i]);
        current_lines[i] = NULL;
        current_lines_alloc[i] = 0;
    }
    line_cache_index = 0;
    current_line_sent = current_line_len = 0;
}

/*
 * Override the input method of the lexer.
 * Read a complete line and save it for error printing.
 * Must be a macro to access yyin.
 */
#undef YY_INPUT
#define YY_INPUT(buf, result, max_size)                                          \
    size_t _avail = current_line_len - current_line_sent;                        \
    if (_avail == 0) {                                                           \
        current_line_sent = 0;                                                   \
        line_cache_index = (line_cache_index + 1) % LINES_TO_CACHE;              \
        const ssize_t _res = getline(&current_lines[line_cache_index],           \
                                     &current_lines_alloc[line_cache_index],     \
                                     yyin);                                      \
        if (_res < 0) {                                                          \
            if (ferror(yyin)) {                                                  \
                YY_FATAL_ERROR("Error reading input");                           \
            }                                                                    \
            _avail = 0;                                                          \
        } else {                                                                 \
            _avail = (size_t)_res;                                               \
        }                                                                        \
        current_line_len = _avail;                                               \
    }                                                                            \
    if (_avail > (size_t)(max_size)) {                                           \
        _avail = (size_t)(max_size);                                             \
    }                                                                            \
    memcpy((buf), current_lines[line_cache_index] + current_line_sent, _avail);  \
    current_line_sent += _avail;                                                 \
    (result) = (int)_avail;

%}
%option nounput
%option noinput
%option noyywrap
%option nodefault
%option yylineno
%option reentrant
%option bison-bridge
%option bison-locations
%%
policy_module { return POLICY_MODULE; }
module { return MODULE; }
type { return TYPE; }
typealias { return TYPEALIAS; }
alias { return ALIAS; }
attribute { return ATTRIBUTE; }
bool { return BOOL; }
typeattribute { return TYPE_ATTRIBUTE; }
roleattribute { return ROLE_ATTRIBUTE; }
role { return ROLE; }
types {  return TYPES; }
attribute_role { return ATTRIBUTE_ROLE; }
allow { return ALLOW; }
allowxperm { return ALLOW_XPERM; }
auditallow { return AUDIT_ALLOW; }
auditallowxperm { return AUDIT_ALLOW_XPERM; }
dontaudit { return DONT_AUDIT; }
dontauditxperm { return DONT_AUDIT_XPERM; }
neverallow { return NEVER_ALLOW; }
neverallowxperm { return NEVER_ALLOW_XPERM; }
type_transition { return TYPE_TRANSITION; }
type_member { return TYPE_MEMBER; }
type_change { return TYPE_CHANGE; }
range_transition { return RANGE_TRANSITION; }
role_transition { return ROLE_TRANSITION; }
optional_policy { return OPTIONAL_POLICY; }
gen_require { return GEN_REQUIRE; }
gen_bool { return GEN_BOOL; }
gen_tunable { return GEN_TUNABLE; }
require { return REQUIRE; }
tunable_policy { return TUNABLE_POLICY; }
ifelse { return IFELSE; }
refpolicywarn { return REFPOLICYWARN; }
class { return CLASS; }
common { return COMMON; }
inherits { return INHERITS; }
if { return IF; }
else { return ELSE; }
ifdef { return IFDEF; }
ifndef { return IFNDEF; }
genfscon { return GENFSCON; }
sid { return SID; }
portcon { return PORTCON; }
netifcon { return NETIFCON; }
nodecon { return NODECON; }
fs_use_trans { return FS_USE_TRANS; }
fs_use_xattr { return FS_USE_XATTR; }
fs_use_task { return FS_USE_TASK; }
define { return DEFINE; }
gen_user { return GEN_USER; }
gen_context { return GEN_CONTEXT; }
permissive { return PERMISSIVE; }
typebounds { return TYPEBOUNDS; }
interface { return INTERFACE; }
template { return TEMPLATE; }
userdebug_or_eng { return USERDEBUG_OR_ENG; }
[0-9]+\.[0-9]+(\.[0-9]+)? { yylval->string = strdup(yytext); return VERSION_NO; }
[0-9]+ { yylval->string = strdup(yytext); return NUMBER; }
[a-zA-Z\$\/][a-zA-Z0-9_\$\*\/\-]* { yylval->string = strdup(yytext); return STRING; }
[0-9a-zA-Z\$\/][a-zA-Z0-9_\$\*\/\-]* { yylval->string = strdup(yytext); return NUM_STRING; }
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} { yylval->string = strdup(yytext); return IPV4; }
([0-9A-Fa-f]{1,4})?\:([0-9A-Fa-f\:])*\:([0-9A-Fa-f]{1,4})? { yylval->string = strdup(yytext); return IPV6; }
\"[a-zA-Z0-9_\.\-\:~\$]*\" { yylval->string = strdup(yytext); return QUOTED_STRING; }
\-[\-ldbcsp][ \t] { return FILE_TYPE_SPECIFIER; }
\( { return OPEN_PAREN; }
\) { return CLOSE_PAREN; }
\, { return COMMA; }
\. { return PERIOD; }
\{ { return OPEN_CURLY; }
\} { return CLOSE_CURLY; }
\: { return COLON; }
\; { return SEMICOLON; }
\` { return BACKTICK; }
\' { return SINGLE_QUOTE; }
\~ { return TILDA; }
\* { return STAR; }
\- { return DASH; }
\&\& { return AND; }
\|\| { return OR; }
\^ { return XOR; }
\!\= { return NOT_EQUAL; }
\! { return NOT; }
\=\= { return EQUAL; }
\#selint\-disable\:\ ?[CSWEF]\-[0-9]+(\,\ ?[CSWEF]\-[0-9]+)*$ { yylval->string = strdup(yytext); return SELINT_COMMAND; }
\#.*$ { return COMMENT; }
dnl(.*)?$ ; /* skip m4 comment lines */
[ \t\n\r] ; /* normally skip whitespace */
. { yylval->symbol = *yytext; return UNKNOWN_TOKEN; }
