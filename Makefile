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

REGRESS = pgaudit
REGRESS_OPTS = --temp-config=$(top_srcdir)/contrib/pgaudit/pgaudit.conf

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
