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

#define AUDIT_NUM_RULES 12

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


enum
{
	AUDIT_RULE_TIMESTAMP = 0,
	AUDIT_RULE_DATABASE,
	AUDIT_RULE_CURRENT_USER,
	AUDIT_RULE_USER,
	AUDIT_RULE_CLASS,
	AUDIT_RULE_COMMAND_TAG,
	AUDIT_RULE_OBJECT_TYPE,
	AUDIT_RULE_OBJECT_ID,
	AUDIT_RULE_APPLICATION_NAME,
	AUDIT_RULE_REMOTE_HOST,
	AUDIT_RULE_REMOTE_PORT,
	AUDIT_RULE_SHUTDOWN_STATUS
};

typedef struct AuditRuleList
{
	char *field;
	int	index;
} AuditRuleList;

typedef struct Rule
{
	char *field;
	char *value;
	bool eq;
} Rule;

typedef struct AuditRuleConfig
{
	char *format;
	Rule rules[AUDIT_NUM_RULES];
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
extern List	*ruleConfig;

/* extern functions */
extern void processAuditConfigFile(char* filename);

extern void pgaudit_set_options(char* name, char* value);
extern void pgaudit_set_output_literal(char* name, char* value);
extern void pgaudit_set_output_integer(char* name, char* value);
extern void pgaudit_set_output_boolean(char* name, char* value);
extern void pgaudit_set_format(char* value);
