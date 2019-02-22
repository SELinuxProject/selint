if HAVE_HELP2MAN
man1_MANS=$(MANPAGES)
EXTRA_DIST=$(man_MANS)
CLEANFILES=$(MANPAGES)

selint.1: ../src/main.c
	$(HELP2MAN) -n "Perform static source code analysis on SELinux policy source files" -N -i selint.h2m -o $@ ../src/selint
endif
