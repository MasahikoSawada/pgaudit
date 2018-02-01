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

#define AUDIT_NUM_RULES 10
#define MAX_NAME_LEN 8192

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
#define OBJECT_TYPE_TOASTVALUE      "TOAST VALUE"
#define OBJECT_TYPE_VIEW            "VIEW"
#define OBJECT_TYPE_MATVIEW         "MATERIALIZED VIEW"
#define OBJECT_TYPE_COMPOSITE_TYPE  "COMPOSITE TYPE"
#define OBJECT_TYPE_FOREIGN_TABLE   "FOREIGN TABLE"
#define OBJECT_TYPE_FUNCTION        "FUNCTION"
#define OBJECT_TYPE_UNKNOWN			"UNKNOWN"

/* These are for configuration parameter */
#define OBJECT_TYPE_CONFIG_TABLE			"TABLE"
#define OBJECT_TYPE_CONFIG_INDEX			"INDEX"
#define OBJECT_TYPE_CONFIG_SEQUENCE			"SEQUENCE"
#define OBJECT_TYPE_CONFIG_TOASTVALUE		"TOAST_VALUE"
#define OBJECT_TYPE_CONFIG_VIEW				"VIEW"
#define OBJECT_TYPE_CONFIG_MATVIEW			"MATERIALIZED_VIEW"
#define OBJECT_TYPE_CONFIG_COMPOSITE_TYPE	"COMPOSITE_TYPE"
#define OBJECT_TYPE_CONFIG_FOREIGN_TABLE	"FOREIGN_TABLE"
#define OBJECT_TYPE_CONFIG_FUNCTION			"FUNCTION"
#define OBJECT_TYPE_CONFIG_UNKNOWN			"UNKNOWN"

/* Bits the object type for filtering object by object_type field */
#define LOG_OBJECT_TABLE			0x0001
#define LOG_OBJECT_INDEX			0x0002
#define LOG_OBJECT_SEQUENCE			0x0004
#define LOG_OBJECT_TOASTVALUE		0x0008
#define LOG_OBJECT_VIEW				0x0010
#define LOG_OBJECT_MATVIEW			0x0020
#define LOG_OBJECT_COMPOSITE_TYPE	0x0040
#define LOG_OBJECT_FOREIGN_TABLE	0x0080
#define LOG_OBJECT_FUNCTION			0x0100
#define LOG_OBJECT_UNKNOWN			0x0200
#define LOG_OBJECT_ALL				0x0FFF

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
extern bool auditLogStatementOnce;
extern char *auditRole;
extern bool logForTest;

extern AuditOutputConfig outputConfig;
extern List	*ruleConfigs;

/* extern functions */
extern void processAuditConfigFile(char* filename);
extern int objecttype_to_bitmap(const char *str, bool config);

extern void pgaudit_set_option(char* name, char* value);
extern void pgaudit_set_output_literal(char* name, char* value);
extern void pgaudit_set_output_integer(char* name, char* value);
extern void pgaudit_set_output_boolean(char* name, char* value);
extern void pgaudit_set_format(char* value);
