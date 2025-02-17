# Summary

SELint is a program to perform static code analysis on SELinux policy source
files.

## Installing from tar download

To install from a downloaded tarball, first install the following dependencies:

On rpm based distros:
* uthash-devel
* libconfuse
* libconfuse-devel
* check
* check-devel

On apt based distros:
* uthash-dev
* libconfuse-dev
* check

Then run:

```
./configure
make
make install
```

## Installing from git

If you are building from a git repo checkout, you'll also need bison, flex,
autotools (automake, autoconf, aclocal, autoreconf) and the autoconf-archive package.
Then you can run `./autogen.sh` to set up autotools and then follow the steps above.

## Usage

```
selint [OPTIONS] FILE [...]
```

### Options

```
-c CONFIGFILE, --config=CONFIGFILE
	Override default config with config specified on command line.  See
	CONFIGURATION section for config file syntax.

--color=COLOR_OPTION
	Configure color output.  Options are on, off and auto (the default).

--context=CONTEXT_PATH
	Also parse any .te or .if files found in CONTEXT_PATH and load symbols
	associated with them for use when checking the policy files to be analyzed.
	No checks are run on these files. Implies -s.

--debug-parser
	Enable debug output for the internal policy parser.
	Very noisy, useful to debug parsing failures.

-d CHECKID, --disable=CHECKID
	Disable check with the given ID.

-e CHECKID, --enable=CHECKID
	Enable check with the given ID.

-E, --only-enabled
	Only run checks that are explicitly enabled with the --enable option.

-F, --fail
	Exit with a non-zero value if any issue was found.

-h, --help
	Show help menu about command line options.

-l LEVEL, --level=LEVEL
	Only list errors with a severity level at or greater than LEVEL.  Options
	are C (convention), S (style), W (warning), E (error), F (fatal error).  See
	SEVERITY LEVELS for more information.  If this option is not specified,
	SELint will default to the level selected in the applicable config file.

--scan-hidden-dirs
	Scan hidden directories.  By default hidden directories (like `.git`) are
	skipped in recursive mode.

-s, --source
	Run in "source mode" to scan a policy source repository that is designed to
	compile into a full system policy.  If this flag is not specified, SELint
	will assume that scanned policy files are intended to be loaded into the
	currently running system policy.

-S, --summary
	Display a summary of issues found after running the analysis.

--summary-only
	Only display a summary of issues found after running the analysis.
	Do not show the individual findings.  Implies -S.

-r, --recursive
	Scan recursively and check all SELinux policy files found.

-v, --verbose
	Enable verbose output

-V, --version
	Show version information and exit.
```

### Configuration

A global configuration is specified at the install prefix supplied to
`./configure` (typically `/usr/local/etc`).  This can be overridden on the command
line using the -c option.

Options specified on the command line override options from the config file.

See the global config file for details on config file syntax.

### Severity levels

SELint messages are assocatied with a severity level, indicating the
significance of the issue.  Available levels are listed below in increasing
order of significance.

* X (extra) - Miscellaneous checks, mainly for policy introspection.
  These must be explicitly enabled with their individual identifier.
* C (convention) - A violation of common style conventions
* S (style) - Stylistic "code smell" that may be associated with unintended
  behavior
* W (warning) - Non standard policy that may result in issues such as run time
  errors or security issues
* E (error) - Important issues that may result in errors at compile time or
  run time
* F (fatal error) - Error that prevents further processing

### SELint exceptions

To eliminate one or more checks on one line, add a comment containing a string
in any of the following formats:

* `selint-disable:E-003`
* `selint-disable: E-003`
* `selint-disable:E-003,E-004`
* `selint-disable: E-003, E-004`

This is currently only supported in te and if files

### Output

SELint outputs messages in the following format:

```
[filename]:[lineno]: ([SEVERITY LEVEL]): [MESSAGE] ([ISSUE ID])
```

For example:

```
example.te:127: (E) Interface from module not in optional_policy block (E-001)
```

### Check IDs

The following checks may be performed:

Extra Checks:

* X-001: Unused interface or template declaration
* X-002: AV rule with excluded source or target (can affect policy binary size)

Convention Checks:

* C-001: Violation of refpolicy te file ordering conventions
* C-004: Interface does not have documentation comment
* C-005: Permissions in av rule or class declaration not ordered
* C-006: Declarations in require block not ordered
* C-007: Redundant type specification instead of self keyword
* C-008: Conditional expression identifier from foreign module

Style Checks:

* S-001: Require block used instead of interface call
* S-002: File context file labels with type not declared in module
* S-003: Unnecessary semicolon
* S-004: Template call from an interface
* S-005: Declaration in interface
* S-006: Bare module statement
* S-007: Call to gen_context omits mls component
* S-008: Unquoted gen_require block
* S-009: Permission macro suffix does not match class name
* S-010: Permission macro usage suggested
* S-011: File context line containing only white spaces

Warning Checks:

* W-001: Type, attribute or userspace class referenced without explicit declaration
* W-002: Type, attribute, role or userspace class used but not listed in require block in interface
* W-003: Unused type, attribute, role or userspace class listed in require block
* W-004: Potentially unescaped regex character in file contexts paths
* W-005: Interface call from module not in optional_policy block
* W-006: Interface call with empty argument
* W-007: Unquoted space in argument of interface call
* W-008: Allow rule with complement or wildcard permission
* W-009: Module name does not match file name
* W-010: Call to unknown interface
* W-011: Declaration in require block not defined in own module
* W-012: Conditional expression contains unknown identifier
* W-013: Incorrect usage of audit_access permission

Error Checks:

* E-002: Bad file context format
* E-003: Nonexistent user listed in fc file
* E-004: Nonexistent role listed in fc file
* E-005: Nonexistent type listed in fc file
* E-006: Declaration and interface with same name
* E-007: Usage of unknown permission or permission macro
* E-008: Usage of unknown class
* E-009: Empty optional or require macro block
* E-010: Usage of unknown simple m4 macro or stray word

Fatal Error Checks:

* F-001: Policy syntax error prevents further processing
* F-002: Internal error in SELint

## Reference policy conventions

To improve the accuracy and avoid false-positives SELint makes some assumptions about
naming conventions and formatting of the policy:

* Type identifiers should end with the suffix `_t`.
* Role identifiers should end with the suffix `_r`.
* Names of noop interfaces for availability checks should end with the suffix `_stub`.
* Permission macros should end with the suffix `_perms`.
* Class set macros should end with the suffix `_class_set`.
* Security class declarations of userspace classes in the security_classes file should be
  declared with a comment including the word `userspace`.
* Interfaces that wrap a file based type-transition should end with the suffix `_filetrans`.
* Interfaces that transforms their arguments, e.g. associate an attribute with them,
  and thus should be handled like a declaration should have one of the following common
  suffixes: `_type`, `_file`, `_domain`, `_node`, `_agent`, `_delivery`, `_sender`,
  `_boolean`, `_content`, `_constrained`, `_executable`, `_exemption`, `_object`
  or `_mountpoint`.
