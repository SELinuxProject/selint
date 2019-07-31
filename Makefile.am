AUTOMAKE_OPTIONS = foreign
SUBDIRS = src . tests . man

selintconfdir = $(sysconfdir)
selintconf_DATA = selint.conf
EXTRA_DIST = selint.conf

check-valgrind:
	CK_FORK=no $(MAKE) -C tests check-valgrind-memcheck-am
	CK_FORK=no $(MAKE) -C tests check-valgrind-sgcheck-am
