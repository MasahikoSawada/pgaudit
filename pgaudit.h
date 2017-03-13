/*
 * pgaudit.h
 *
 * Copyright (c) 2017, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * This is an internal header file for pgaudit*.c, not for user programs.
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit.h
 */
#ifndef PGAUDIT_H
#define PGAUDIT_H

#include "postgres.h"
#include "lib/stringinfo.h"
#include "nodes/pg_list.h"
#include "tcop/utility.h"
#include "tcop/deparse_utility.h"

#ifndef _SYS_SYSLOG_H
#include <syslog.h>
#endif

/*
 * AUDIT_ELOG() is for audit logging differ to ereport. Now that we emit the audit
 * log in  pgaudit_emit_log_hook, it's possible to emit the log recusively. To
 * prevent it, we introduece a variable emitAuditLogCalled, which is 0 by default.
 * > 1 means that we alreadby emited some logs, so we don't need to emit log anymore.
 *
 * In case where we want to use elog/ereport, we should use AUDIT_ELOG/EREPORT instead
 * which easily avoid to emit log recusively.
 */
extern int emitAuditLogCalled;
#define START_AUDIT_LOGGING()	(emitAuditLogCalled++)
#define END_AUDIT_LOGGING() 	(emitAuditLogCalled--)
#define AUDIT_ELOG(level, ...) \
	do { \
		START_AUDIT_LOGGING(); \
		elog((level), __VA_ARGS__); \
		END_AUDIT_LOGGING(); \
		emitAuditLogCalled--; \
	} while (0)
#define AUDIT_EREPORT(level, ...) \
	do { \
		START_AUDIT_LOGGING(); \
		ereport((level), __VA_ARGS__); \
		END_AUDIT_LOGGING(); \
	} while (0)

/*
 * An AuditEvent represents an operation that potentially affects a single
 * object.  If a statement affects multiple objects then multiple AuditEvents
 * are created to represent them.
 */
typedef struct
{
    int64 statementId;          /* Simple counter */
    int64 substatementId;       /* Simple counter */

    LogStmtLevel logStmtLevel;  /* From GetCommandLogLevel when possible,
                                   generated when not. */
    NodeTag commandTag;         /* same here */
    const char *command;        /* same here */
    const char *objectType;     /* From event trigger when possible,
                                   generated when not. */
    char *objectName;           /* Fully qualified object identification */
    const char *commandText;    /* sourceText / queryString */
    ParamListInfo paramList;    /* QueryDesc/ProcessUtility parameters */

    bool granted;               /* Audit role has object permissions? */
    bool logged;                /* Track if we have logged this event, used
                                   post-ProcessUtility to make sure we log */
    bool statementLogged;       /* Track if we have logged the statement */
} AuditEvent;

/*
 * A simple FIFO queue to keep track of the current stack of audit events.
 */
typedef struct AuditEventStackItem
{
    struct AuditEventStackItem *next;

    AuditEvent auditEvent;

    int64 stackId;

    MemoryContext contextAudit;
    MemoryContextCallback contextCallback;
} AuditEventStackItem;

extern pg_time_t auditTimestampOfDay;
#endif
