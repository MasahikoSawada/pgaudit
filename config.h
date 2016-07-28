/*
 * config.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * IDENTIFICATION
 *           pgaudit/config.h
 */

#include "postgres.h"
#include "nodes/pg_list.h"
#include "utils/builtins.h"
#include "pgtime.h"

#include "rule.h"

#define AUDIT_NUM_RULES 11
#define MAX_NAME_LEN 8192

/*
 * String constants for log classes - used when processing tokens in the
 * pgaudit.log GUC.
 */
#define CLASS_BACKUP	"BACKUP"
#define CLASS_CONNECT	"CONNECT"
#define CLASS_DDL       "DDL"
#define CLASS_ERROR		"ERROR"
#define CLASS_FUNCTION  "FUNCTION"
#define CLASS_MISC      "MISC"
#define CLASS_READ      "READ"
#define CLASS_ROLE      "ROLE"
#define CLASS_WRITE     "WRITE"
#define	CLASS_SYSTEM	"SYSTEM"

#define CLASS_NONE      "NONE"
#define CLASS_ALL       "ALL"

/* Defines the classes for filtering operation by class field */
#define LOG_BACKUP		(1 << 0)	/* Backbackup through replication */
#define LOG_CONNECT		(1 << 1)	/* connection, disconnection */
#define LOG_DDL         (1 << 2)    /* CREATE/DROP/ALTER objects */
#define LOG_ERROR		(1 << 3)	/* General ERROR message */
#define LOG_FUNCTION    (1 << 4)    /* Functions and DO blocks */
#define LOG_MISC        (1 << 5)    /* Statements not covered */
#define LOG_READ        (1 << 6)    /* SELECTs */
#define LOG_ROLE        (1 << 7)    /* GRANT/REVOKE, CREATE/ALTER/DROP ROLE */
#define LOG_WRITE       (1 << 8)    /* INSERT, UPDATE, DELETE, TRUNCATE */
#define LOG_SYSTEM		(1 << 9)	/* Server startup, end, interrupt */

#define LOG_NONE        0               /* nothing */
#define LOG_ALL         (0xFFFFFFFF)    /* All */

/*
 * Object type, used for SELECT/DML statements and function calls.
 *
 * For relation objects, this is essentially relkind (though we do not have
 * access to a function which will just return a string given a relkind;
 * getRelationTypeDescription() comes close but is not public currently).
 *
 * We also handle functions, so it isn't quite as simple as just relkind.
 *
 * This should be kept consistent with what is returned from
 * pg_event_trigger_ddl_commands(), as that's what we use for DDL.
 */
#define OBJECT_TYPE_TABLE           "TABLE"
#define OBJECT_TYPE_INDEX           "INDEX"
#define OBJECT_TYPE_SEQUENCE        "SEQUENCE"
#define OBJECT_TYPE_TOASTVALUE      "TOAST TABLE"
#define OBJECT_TYPE_VIEW            "VIEW"
#define OBJECT_TYPE_MATVIEW         "MATERIALIZED VIEW"
#define OBJECT_TYPE_COMPOSITE_TYPE  "COMPOSITE TYPE"
#define OBJECT_TYPE_FOREIGN_TABLE   "FOREIGN TABLE"
#define OBJECT_TYPE_FUNCTION        "FUNCTION"

#define OBJECT_TYPE_UNKNOWN         "UNKNOWN"

/* BIts the object type for filtering object by object_type field */
#define LOG_OBJECT_TABLE			(1 << 0)
#define LOG_OBJECT_INDEX			(1 << 1)
#define LOG_OBJECT_SEQUENCE			(1 << 2)
#define LOG_OBJECT_TOASTVALUE		(1 << 3)
#define LOG_OBJECT_VIEW				(1 << 4)
#define LOG_OBJECT_MATVIEW			(1 << 5)
#define LOG_OBJECT_COMPOSITE_TYPE	(1 << 6)
#define LOG_OBJECT_FOREIGN_TABLE	(1 << 7)
#define LOG_OBJECT_FUNCTION			(1 << 8)
#define LOG_ALL_OBJECT_TYPE 		0x1F

typedef struct AuditOutputConfig
{
	char *logger;
	char *level;
	char *pathlog;
	char *facility;
	char *priority;
	char *ident;
	char *option;
} AuditOutputConfig;

typedef struct AuditRule
{
	char *field;
	void *values;
	bool eq;
	int	nval;
	int	type;
} AuditRule;

typedef struct AuditRuleConfig
{
	char *format;
	AuditRule rules[AUDIT_NUM_RULES];
} AuditRuleConfig;

/* Global configuration variables */
extern bool auditLogCatalog;
extern char *auditLogLevelString;
extern int auditLogLevel;
extern bool auditLogParameter;
extern bool auditLogRelation;
extern bool auditLogStatementOnce;
extern char *auditRole;

extern AuditOutputConfig *outputConfig;
extern List	*ruleConfigs;

/* extern functions */
extern void processAuditConfigFile(char* filename);

extern void pgaudit_set_options(char* name, char* value);
extern void pgaudit_set_output_literal(char* name, char* value);
extern void pgaudit_set_output_integer(char* name, char* value);
extern void pgaudit_set_output_boolean(char* name, char* value);
extern void pgaudit_set_format(char* value);
