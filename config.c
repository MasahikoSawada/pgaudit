/*
 * config.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * This function group is one that is called from
 * the action part of pgaudit configuration file parsing.
 *
 * IDENTIFICATION
 *           pgaudit/config.c
 */

#include "postgres.h"

#include <stdio.h>
#include <sys/stat.h>
#include "config.h"

enum
{
	AUDIT_NAME = 1,
	AUDIT_INT = 2,
	AUDIT_BOOLEAN = 3,
	AUDIT_OP = 5,
	AUDIT_FIELD_OUTPUT = 6,
	AUDIT_FIELD_OPTIONS = 7,
	AUDIT_FIELD_RULE = 8,
	AUDIT_SECTION_RULE = 9,
	AUDIT_SECTION_OPTIONS = 10,
	AUDIT_SECTION_OUTPUT = 11,
	AUDIT_EOL = 12,
	AUDIT_EOF = 13
};

struct AuditRuleList auditRuleList[] =
{
	{"timestamp", AUDIT_RULE_TIMESTAMP},
	{"database", AUDIT_RULE_DATABASE},
	{"current_user", AUDIT_RULE_CURRENT_USER},
	{"user", AUDIT_RULE_USER},
	{"class", AUDIT_RULE_CLASS},
	{"command_tag", AUDIT_RULE_COMMAND_TAG},
	{"object_type", AUDIT_RULE_OBJECT_TYPE},
	{"object_id", AUDIT_RULE_OBJECT_ID},
	{"application_name", AUDIT_RULE_APPLICATION_NAME},
	{"remote_host", AUDIT_RULE_REMOTE_HOST},
	{"remote_port", AUDIT_RULE_REMOTE_PORT},
	{"shutdown_status", AUDIT_RULE_SHUTDOWN_STATUS}
};

/*
 * GUC variable for pgaudit.log_catalog
 *
 * Administrators can choose to NOT log queries when all relations used in
 * the query are in pg_catalog.  Interactive sessions (eg: psql) can cause
 * a lot of noise in the logs which might be uninteresting.
 */
bool auditLogCatalog = true;

/*
 * GUC variable for pgaudit.log_level
 *
 * Administrators can choose which log level the audit log is to be logged
 * at.  The default level is LOG, which goes into the server log but does
 * not go to the client.  Set to NOTICE in the regression tests.
 */
char *auditLogLevelString = NULL;
int auditLogLevel = LOG;

/*
 * GUC variable for pgaudit.log_parameter
 *
 * Administrators can choose if parameters passed into a statement are
 * included in the audit log.
 */
bool auditLogParameter = false;

/*
 * GUC variable for pgaudit.log_relation
 *
 * Administrators can choose, in SESSION logging, to log each relation involved
 * in READ/WRITE class queries.  By default, SESSION logs include the query but
 * do not have a log entry for each relation.
 */
bool auditLogRelation = false;

/*
 * GUC variable for pgaudit.log_statement_once
 *
 * Administrators can choose to have the statement run logged only once instead
 * of on every line.  By default, the statement is repeated on every line of
 * the audit log to facilitate searching, but this can cause the log to be
 * unnecessairly bloated in some environments.
 */
bool auditLogStatementOnce = false;

/*
 * GUC variable for pgaudit.role
 *
 * Administrators can choose which role to base OBJECT auditing off of.
 * Object-level auditing uses the privileges which are granted to this role to
 * determine if a statement should be logged.
 */
char *auditRole = NULL;

/* Global configuration variables */
AuditOutputConfig *outputConfig;
List	*ruleConfig;

static int	audit_parse_state = 0;

/* Proto type */
static bool	str_to_bool(const char *str);
static bool op_to_bool(const char *str);

static void validate_settings(char *field, char *op, char *value,
								AuditRuleConfig *rconf);
static void assign_pgaudit_log_level(char *newVal);
static void set_default_rule(AuditRuleConfig *rconf);

static bool
op_to_bool(const char *str)
{
	if (strcmp(str, "=") != 0)
		return true;
	else if (strcmp(str, "!=") != 0)
		return false;

	return false;
}
static bool
str_to_bool(const char *str)
{
	if (strcmp(str, "on") != 0 ||
		strcmp(str, "true") != 0 ||
		strcmp(str, "1") != 0)
		return true;
	else if (strcmp(str, "off") != 0 ||
			 strcmp(str, "false") != 0 ||
			 strcmp(str, "0") != 0)
		return false;

	return false;
}

static void
set_default_rule(AuditRuleConfig *rconf)
{
	int i;
	for (i = 0; i < AUDIT_NUM_RULES; i++)
	{
		Rule *rule = &(rconf->rules[i]);

		rule->field = NULL;
		rule->value = NULL;
		rule->eq = false;
	}
}

/*
 * Take a pgaudit.log_level value such as "debug" and check that is is valid.
 * Return the enum value so it does not have to be checked again in the assign
 * function.
 */
static void
assign_pgaudit_log_level(char *newVal)
{
    /* Find the log level enum */
    if (pg_strcasecmp(newVal, "debug") == 0)
        auditLogLevel = DEBUG2;
    else if (pg_strcasecmp(newVal, "debug5") == 0)
        auditLogLevel = DEBUG5;
    else if (pg_strcasecmp(newVal, "debug4") == 0)
        auditLogLevel = DEBUG4;
    else if (pg_strcasecmp(newVal, "debug3") == 0)
        auditLogLevel = DEBUG3;
    else if (pg_strcasecmp(newVal, "debug2") == 0)
        auditLogLevel = DEBUG2;
    else if (pg_strcasecmp(newVal, "debug1") == 0)
        auditLogLevel = DEBUG1;
    else if (pg_strcasecmp(newVal, "info") == 0)
        auditLogLevel = INFO;
    else if (pg_strcasecmp(newVal, "notice") == 0)
        auditLogLevel = NOTICE;
    else if (pg_strcasecmp(newVal, "warning") == 0)
        auditLogLevel = WARNING;
    else if (pg_strcasecmp(newVal, "log") == 0)
        auditLogLevel = LOG;
}

static void
validate_settings(char *field, char *op,char *value,
					AuditRuleConfig *rconf)
{
	/* Validation for output section */
	if (audit_parse_state == AUDIT_SECTION_OUTPUT)
	{
		if ((strcmp(field, "logger") == 0))
		{
			outputConfig->logger = value;
		}
		else if ((strcmp(field, "level") == 0))
		{
			auditLogLevelString = value;
			assign_pgaudit_log_level(auditLogLevelString);
		}
		else if ((strcmp(field, "pathlog") == 0))
		{
			outputConfig->pathlog = value;
		}
		else if ((strcmp(field, "facility") == 0))
		{
			outputConfig->facility = value;

		}
		else if ((strcmp(field, "priority") == 0))
		{
			outputConfig->priority = value;

		}
		else if ((strcmp(field, "ident") == 0))
		{
			outputConfig->ident = value;

		}
		else if ((strcmp(field, "option") == 0))
		{
			outputConfig->option = value;

		}
	}
	/* Validation for options section */
	else if (audit_parse_state == AUDIT_SECTION_OPTIONS)
	{
		if ((strcmp(field, "role") == 0))
		{
			auditRole = value;
		}
		else if ((strcmp(field, "log_catalog") == 0))
		{
			auditLogCatalog = str_to_bool(value);
		}
		else if ((strcmp(field, "log_parameter") == 0))
		{
			auditLogParameter = str_to_bool(value);
		}
		else if ((strcmp(field, "log_statement_once") == 0))
		{
			auditLogStatementOnce = str_to_bool(value);

		}

	}
	/* Validation for rule section */
	else if (audit_parse_state == AUDIT_SECTION_RULE)
	{
		elog(WARNING, "hogehgo %s", field);
		if ((strcmp(field, "format") == 0))
		{
			rconf->format = value;
		}
		else
		{
			int i;

			for (i = 0; i < AUDIT_NUM_RULES; i++)
			{
				if (strcasecmp(field, (auditRuleList[i]).field) == 0)
				{
					int index = auditRuleList[i].index;
					Rule *rule = &(rconf->rules[index]);

					rule->field = field;
					rule->value = value;
					rule->eq = op_to_bool(op);
				}
			}
		}
	}
	else
	{
		/* error */
	}

}
	
#include "pgaudit_scan.c"
