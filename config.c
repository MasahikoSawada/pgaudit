/*
 * config.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * IDENTIFICATION
 *           pgaudit/config.c
 */

#include "postgres.h"

#include <stdio.h>
#include <sys/stat.h>

#include "config.h"

/* Definition for parsing configration file */
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

/*
 * The template definition for audit rule. Each rule section
 * has this array of AuditRule and overwrite value to appropriate
 * field.
 */
struct AuditRule rules_template[] =
{
	{"timestamp", NULL, false, 0, AUDIT_RULE_TYPE_TIMESTAMP},
	{"database", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"current_user", NULL, false, 0, AUDIT_RULE_TYPE_INT},
	{"user", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"class", NULL, false, 0, AUDIT_RULE_TYPE_BITMAP},
	{"command_tag", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"object_type", NULL, false, 0, AUDIT_RULE_TYPE_BITMAP},
	{"object_id", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"application_name", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"remote_host", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"remote_port", NULL, false, 0, AUDIT_RULE_TYPE_INT}
};

/*
 * Administrators can choose to NOT log queries when all relations used in
 * the query are in pg_catalog.  Interactive sessions (eg: psql) can cause
 * a lot of noise in the logs which might be uninteresting.
 */
bool auditLogCatalog = true;

/*
 * Administrators can choose which log level the audit log is to be logged
 * at.  The default level is LOG, which goes into the server log but does
 * not go to the client.  Set to NOTICE in the regression tests.
 */
char *auditLogLevelString = NULL;
int auditLogLevel = LOG;

/*
 * Administrators can choose if parameters passed into a statement are
 * included in the audit log.
 */
bool auditLogParameter = false;

/*
 * Administrators can choose, in SESSION logging, to log each relation involved
 * in READ/WRITE class queries.  By default, SESSION logs include the query but
 * do not have a log entry for each relation.
 */
bool auditLogRelation = false;

/*
 * Administrators can choose to have the statement run logged only once instead
 * of on every line.  By default, the statement is repeated on every line of
 * the audit log to facilitate searching, but this can cause the log to be
 * unnecessairly bloated in some environments.
 */
bool auditLogStatementOnce = false;

/*
 * Administrators can choose which role to base OBJECT auditing off of.
 * Object-level auditing uses the privileges which are granted to this role to
 * determine if a statement should be logged.
 */
char *auditRole = "";

/* Global variable for output and rule sections */
AuditOutputConfig *outputConfig;
List	*ruleConfigs;

static int	audit_parse_state = 0;

/* Primiive functions */
static bool	str_to_bool(const char *str);
static bool op_to_bool(const char *str);
static pg_time_t str_to_timestamp(const char *str);
static int class_to_bitmap(const char *str);
static int objecttype_to_bitmap(const char *str);
static char *audit_scanstr(const char *str);

/* Function for configuration settings */
static void validate_settings(char *field, char *op, char *value,
								AuditRuleConfig *rconf);
static void assign_pgaudit_log_level(char *newVal);

/*
 * Return bitmap bit for LOG_XXX corresponding CLASS_XXX
 */
static int
class_to_bitmap(const char *str)
{
	int class;

	if (pg_strcasecmp(str, CLASS_BACKUP) == 0)
		class = LOG_BACKUP;
	else if (pg_strcasecmp(str, CLASS_CONNECT) == 0)
		class = LOG_CONNECT;
	else if (pg_strcasecmp(str, CLASS_ERROR) == 0)
		class = LOG_ERROR;
	else if (pg_strcasecmp(str, CLASS_NONE) == 0)
		class = LOG_NONE;
	else if (pg_strcasecmp(str, CLASS_ALL) == 0)
		class = LOG_ALL;
	else if (pg_strcasecmp(str, CLASS_DDL) == 0)
		class = LOG_DDL;
	else if (pg_strcasecmp(str, CLASS_FUNCTION) == 0)
		class = LOG_FUNCTION;
	else if (pg_strcasecmp(str, CLASS_MISC) == 0)
		class = LOG_MISC;
	else if (pg_strcasecmp(str, CLASS_READ) == 0)
		class = LOG_READ;
	else if (pg_strcasecmp(str, CLASS_ROLE) == 0)
		class = LOG_ROLE;
	else if (pg_strcasecmp(str, CLASS_WRITE) == 0)
		class = LOG_WRITE;
	else if (pg_strcasecmp(str, CLASS_SYSTEM) == 0)
		class = LOG_SYSTEM;

	return class;
}

/*
 * Return bitmap bit for LOG_OBJECT_XXX corresponding OBJECT_TYPE_XXX
 */
static int
objecttype_to_bitmap(const char *str)
{
	int object_type;

	if (pg_strcasecmp(str, OBJECT_TYPE_TABLE) == 0)
		object_type = LOG_OBJECT_TABLE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_INDEX) == 0)
		object_type = LOG_OBJECT_INDEX;
	else if (pg_strcasecmp(str, OBJECT_TYPE_SEQUENCE) == 0)
		object_type = LOG_OBJECT_SEQUENCE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_TOASTVALUE) == 0)
		object_type = LOG_OBJECT_TOASTVALUE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_VIEW) == 0)
		object_type = LOG_OBJECT_VIEW;
	else if (pg_strcasecmp(str, OBJECT_TYPE_MATVIEW) == 0)
		object_type = LOG_OBJECT_MATVIEW;
	else if (pg_strcasecmp(str, OBJECT_TYPE_COMPOSITE_TYPE) == 0)
		object_type = LOG_OBJECT_COMPOSITE_TYPE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_FOREIGN_TABLE) == 0)
		object_type = LOG_OBJECT_FOREIGN_TABLE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_FUNCTION) == 0)
		object_type = LOG_OBJECT_FUNCTION;

	return object_type;
}

/*
 * Scan though str variable while eliminating the white space
 * and \' (single-quotation) at head and tail, and then return
 * copied string.
 */
static char*
audit_scanstr(const char *str)
{
	int len = strlen(str);
	int newlen;
	int i;
	char *newStr;
	char buf[MAX_NAME_LEN];
	char *bp = buf;

	/* Except for \' at head and tail */
	for (i = 1; i < (len - 1); i++)
	{
		/* Skip white space */
		if (str[i] == ' ')
			continue;

		*bp = str[i];
		bp++;
	}

	newlen = bp - buf;
	buf[newlen] = '\0';
	newStr = pstrdup(buf);

	return newStr;
}

/* Convert string to timestamp */
static pg_time_t
str_to_timestamp(const char *str)
{
	pg_time_t ret;
	int hour, min, sec;

	sscanf(str, "%d:%d:%d", &hour, &min, &sec);
	ret = hour * 3600 + min * 60 + sec;

	return ret;
}

/*
 * Convert operation string to boolean value representing
 * if equal or not.
 */
static bool
op_to_bool(const char *str)
{
	if (strcmp(str, "=") == 0)
		return true;
	else if (strcmp(str, "!=") == 0)
		return false;

	return false;
}

/* Convert boolean string to boolean value */
static bool
str_to_bool(const char *str)
{
	if (strcmp(str, "on") == 0 ||
		strcmp(str, "true") == 0 ||
		strcmp(str, "1") == 0)
		return true;
	else if (strcmp(str, "off") == 0 ||
			 strcmp(str, "false") == 0 ||
			 strcmp(str, "0") == 0)
		return false;

	return false;
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

/*
 * This routine valudates the configuration using given informations;
 * field, operation, value. We have three types of section output,
 * option and rule, and each section can hvae some field.
 */
static void
validate_settings(char *field, char *op,char *value,
					AuditRuleConfig *rconf)
{
	/* Validation for output section */
	if (audit_parse_state == AUDIT_SECTION_OUTPUT)
	{
		if ((strcmp(field, "logger") == 0))
			outputConfig->logger = value;
		else if ((strcmp(field, "level") == 0))
		{
			outputConfig->level = value;
		}
		else if ((strcmp(field, "pathlog") == 0))
			outputConfig->pathlog = value;
		else if ((strcmp(field, "facility") == 0))
			outputConfig->facility = value;
		else if ((strcmp(field, "priority") == 0))
			outputConfig->priority = value;
		else if ((strcmp(field, "ident") == 0))
			outputConfig->ident = value;
		else if ((strcmp(field, "option") == 0))
			outputConfig->option = value;
	}
	/* Validation for options section */
	else if (audit_parse_state == AUDIT_SECTION_OPTIONS)
	{
		if ((strcmp(field, "role") == 0))
			auditRole = value;
		else if ((strcmp(field, "log_catalog") == 0))
			auditLogCatalog = str_to_bool(value);
		else if ((strcmp(field, "log_parameter") == 0))
			auditLogParameter = str_to_bool(value);
		else if ((strcmp(field, "log_statement_once") == 0))
			auditLogStatementOnce = str_to_bool(value);
		else if ((strcmp(field, "log_level") == 0))
		{
			auditLogLevelString = value;
			assign_pgaudit_log_level(auditLogLevelString);
		}

	}
	/* Validation for rule section */
	else if (audit_parse_state == AUDIT_SECTION_RULE)
	{
		int i;

		if ((strcmp(field, "format") == 0))
			rconf->format = value;
		else
		{
			/*
			 * THe rule section have their rules as an array. We
			 * validate it to appropriate element.
			 */
			for (i = 0; i < AUDIT_NUM_RULES; i++)
			{
				if (strcasecmp(field, rules_template[i].field) == 0)
				{
					AuditRule *rule = &(rconf->rules[i]);
					List *value_list;
					ListCell *cell;
					int	list_len;

					/* The value is an CSV format */
					if (!SplitIdentifierString(value, ',', &value_list))
					{
						/* error */
					}

					list_len = list_length(value_list);

					/* Process value_list using appropriate method */
					if (rule->type == AUDIT_RULE_TYPE_INT)
					{
						int *int_values = palloc(sizeof(int) * list_len);

						/*
						 * We expect that the format of integer type value
						 * is '123, 234, ...'.
						 */
						foreach(cell, value_list)
						{
							int val = atoi((char *) lfirst(cell));
							int_values[rule->nval] = val;
							rule->nval++;
						}

						rule->values = int_values;
						rule->eq = op_to_bool(op);
					}
					else if (rule->type == AUDIT_RULE_TYPE_STRING)
					{
						char **str_values = palloc(sizeof(char *) * list_len);
						int i;

						for (i = 0; i < list_len; i++)
							str_values[i] = palloc(sizeof(char) * MAX_NAME_LEN);

						/*
						 * We expect that the format of string type value
						 * is 'hoge, bar, ...'.
						 */
						foreach(cell, value_list)
						{
							char *val = (char *)lfirst(cell);
							int len = strlen(val);

							memcpy(str_values[rule->nval], val, len);
							str_values[rule->nval][len] = '\0';
							rule->nval++;
						}

						rule->values = str_values;
						rule->eq = op_to_bool(op);
					}
					else if (rule->type == AUDIT_RULE_TYPE_BITMAP)
					{
						int *bitmap = (int *) palloc(sizeof(int));
						*bitmap = 0;

						/*
						 * We expect that the format of string type value
						 * is 'write, read, ...'. Compute bitmap for filtering.
						 */
						foreach(cell, value_list)
						{
							char *val = (char *)lfirst(cell);

							/*
							 * Only "class" and "object_type" field are
							 * the type of bitmap so far.
							 */
							if (strcasecmp(field, "class") == 0)
								*bitmap |= class_to_bitmap(val);
							else if (strcasecmp(field, "object_type") == 0)
								*bitmap |= objecttype_to_bitmap(val);
						}

						/*
						 * For bitmap type, the number of values of rule.values
						 * should be 1 because it's a bitmap.
						 */
						rule->nval = 1;
						rule->values = bitmap;
						rule->eq = op_to_bool(op);
					}
					else if (rule->type == AUDIT_RULE_TYPE_TIMESTAMP)
					{
						pg_time_t *ts_values = palloc(sizeof(pg_time_t) * list_len * 2);

						/*
						 * We expect that the format of timestamp type value
						 * is 'HH:MM:SS-HH:MM:SS, HH:MM:SS-HH:MM:SS, ...'.
						 * We extract it and get string representing range.
						 */
						foreach(cell, value_list)
						{
							List *ts_list;
							ListCell *ts_cell;
							char *range_string = (char *)lfirst(cell);

							/* The timestamp range should be separated by '-' */
							if (!SplitIdentifierString(range_string, '-', &ts_list))
							{
								/* error */
							}

							/* We expect that the format of each ts_cell is 'HH:MM:SS' */
							foreach(ts_cell, ts_list)
							{
								pg_time_t ts = str_to_timestamp((char *)lfirst(ts_cell));
								ts_values[rule->nval] = ts;
								rule->nval++;
							}
						}

						rule->values = ts_values;
						rule->eq = op_to_bool(op);
					}

					break;
				} /* found corresponding rule */
			} /* loop for rules_template */
		}
	}
	else
	{
		/* error */
	}
}

#include "pgaudit_scan.c"
