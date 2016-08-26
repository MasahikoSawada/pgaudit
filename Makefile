#####################################################################
# Makefile
#
# Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
#
#####################################################################
# contrib/pg_audit/Makefile# contrib/pg_audit/Makefile

MODULE_big = pgaudit
OBJS = pgaudit.o config.o rule.o

EXTENSION = pgaudit
DATA = pgaudit--1.0.sql
PGFILEDESC = "pgAudit - An audit logging extension for PostgreSQL"

all: pgaudit.o

config.o: pgaudit_scan.c

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pgaudit
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

# Regression test for all of rules.
# XXX : we must add existing 'pgaudit' regression test.
REGRESSCHECKS=database object_type
installcheck:
	$(pg_regress_installcheck) \
		--temp-config=./conf/postgresql.conf \
		--temp-instance=./tmp_check \
		$(REGRESSCHECKS)
