if HAVE_HELP2MAN
man_MANS=$(MANPAGES)
EXTRA_DIST=$(man_MANS)
CLEANFILES=$(MANPAGES)

selint.1: ../src/selint
	$(HELP2MAN) -n "Perform static source code analysis on SELinux policy source files" -N -o $@ $<
endif
