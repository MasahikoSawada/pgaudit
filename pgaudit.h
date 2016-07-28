/*
 * pgaudit.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
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

#endif
