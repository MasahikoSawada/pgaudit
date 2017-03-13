/*
 * config.c
 *
 * Copyright (c) 2017, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * IDENTIFICATION
 *           pgaudit/config.c
 */

#include "postgres.h"

#include <stdio.h>
#include <sys/stat.h>

#include "fmgr.h"
#include "utils/date.h"
#include "utils/nabstime.h"
#include "utils/timestamp.h"

#include "config.h"
#include "pgaudit.h"

/* Definition for parsing configration file */
enum
{
	AUDIT_NAME = 1,
	AUDIT_INT = 2,
	AUDIT_BOOLEAN = 3,
	AUDIT_OP = 5,
	AUDIT_FIELD_OUTPUT = 6,
	AUDIT_FIELD_OPTION = 7,
	AUDIT_FIELD_RULE = 8,
	AUDIT_SECTION_RULE = 9,
	AUDIT_SECTION_OPTION = 10,
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
	{"audit_role", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"class", NULL, false, 0, AUDIT_RULE_TYPE_BITMAP},
	{"command_tag", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"object_type", NULL, false, 0, AUDIT_RULE_TYPE_BITMAP},
	{"object_name", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"application_name", NULL, false, 0, AUDIT_RULE_TYPE_STRING},
	{"remote_host", NULL, false, 0, AUDIT_RULE_TYPE_STRING}
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
AuditOutputConfig outputConfig;
List	*ruleConfigs;
bool	logForTest = false;

static int	audit_parse_state = 0;

/* Primitive functions */
static bool	str_to_bool(const char *str);
static bool op_to_bool(const char *str);
static TimeADT str_to_timestamp(const char *str);
static int class_to_bitmap(const char *str);
static char *audit_scanstr(const char *str);
static char *get_auditsection_string(int section);

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
 * Return bitmap bit for LOG_OBJECT_XXX corresponding OBJECT_TYPE_XXXX.
 * If config is ture, we're interested in configurable setting value rather
 * than object type given by event trigger. If config is false, all type
 * of object types are acceptable.
 */
int
objecttype_to_bitmap(const char *str, bool config)
{
	int object_type;

	if (pg_strcasecmp(str, OBJECT_TYPE_TABLE) == 0 ||
		pg_strcasecmp(str, OBJECT_TYPE_CONFIG_TABLE) == 0)
		object_type = LOG_OBJECT_TABLE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_INDEX) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_INDEX) == 0)
		object_type = LOG_OBJECT_INDEX;
	else if (pg_strcasecmp(str, OBJECT_TYPE_SEQUENCE) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_SEQUENCE) == 0)
		object_type = LOG_OBJECT_SEQUENCE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_TOASTVALUE) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_TOASTVALUE) == 0)
		object_type = LOG_OBJECT_TOASTVALUE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_VIEW) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_VIEW) == 0)
		object_type = LOG_OBJECT_VIEW;
	else if (pg_strcasecmp(str, OBJECT_TYPE_MATVIEW) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_MATVIEW) == 0)
		object_type = LOG_OBJECT_MATVIEW;
	else if (pg_strcasecmp(str, OBJECT_TYPE_COMPOSITE_TYPE) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_COMPOSITE_TYPE) ==0)
		object_type = LOG_OBJECT_COMPOSITE_TYPE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_FOREIGN_TABLE) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_FOREIGN_TABLE) ==0)
		object_type = LOG_OBJECT_FOREIGN_TABLE;
	else if (pg_strcasecmp(str, OBJECT_TYPE_FUNCTION) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_FUNCTION) == 0)
		object_type = LOG_OBJECT_FUNCTION;
	else if (pg_strcasecmp(str, OBJECT_TYPE_UNKNOWN) == 0 ||
			 pg_strcasecmp(str, OBJECT_TYPE_CONFIG_UNKNOWN) == 0)
		object_type = LOG_OBJECT_UNKNOWN;
	else
	{
		if (config)
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("invalid value \"%s\" for object_type", str)));
		else
			/* object type by event trigger must be logged */
			object_type = LOG_OBJECT_ALL;
	}

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
static TimeADT
str_to_timestamp(const char *str)
{
	return DatumGetTimeADT(DirectFunctionCall1(time_in, CStringGetDatum(str)));
}

/*
 * Convert operation string to boolean value representing
 * if equal or not.
 */
static bool
op_to_bool(const char *str)
{
	if (pg_strcasecmp(str, "=") == 0)
		return true;
	else if (pg_strcasecmp(str, "!=") == 0)
		return false;

	return false;
}

/* Convert boolean string to boolean value */
static bool
str_to_bool(const char *str)
{
	if (pg_strcasecmp(str, "on") == 0 ||
		pg_strcasecmp(str, "true") == 0 ||
		pg_strcasecmp(str, "1") == 0)
		return true;
	else if (pg_strcasecmp(str, "off") == 0 ||
			 pg_strcasecmp(str, "false") == 0 ||
			 pg_strcasecmp(str, "0") == 0)
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

/* Return section name string data */
static char *
get_auditsection_string(int section)
{
	switch(section)
	{
		case AUDIT_SECTION_OUTPUT:
			return "output section";
			break;
		case AUDIT_SECTION_OPTION:
			return "option section";
			break;
		case AUDIT_SECTION_RULE:
			return "rule section";
		default:
			return "unknown";
	}
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
		if ((pg_strcasecmp(field, "logger") == 0))
			outputConfig.logger = value;
		else if ((pg_strcasecmp(field, "level") == 0))
			outputConfig.level = value;
		else if ((pg_strcasecmp(field, "pathlog") == 0))
			outputConfig.pathlog = value;
		else if ((pg_strcasecmp(field, "facility") == 0))
			outputConfig.facility = value;
		else if ((pg_strcasecmp(field, "priority") == 0))
			outputConfig.priority = value;
		else if ((pg_strcasecmp(field, "ident") == 0))
			outputConfig.ident = value;
		else if ((pg_strcasecmp(field, "option") == 0))
			outputConfig.option = value;
	}
	/* Validation for option section */
	else if (audit_parse_state == AUDIT_SECTION_OPTION)
	{
		if ((pg_strcasecmp(field, "role") == 0))
			auditRole = value;
		else if ((pg_strcasecmp(field, "log_catalog") == 0))
			auditLogCatalog = str_to_bool(value);
		else if ((pg_strcasecmp(field, "log_parameter") == 0))
			auditLogParameter = str_to_bool(value);
		else if ((pg_strcasecmp(field, "log_statement_once") == 0))
			auditLogStatementOnce = str_to_bool(value);
		else if ((pg_strcasecmp(field, "log_for_test") == 0))
			logForTest = str_to_bool(value);
		else if ((pg_strcasecmp(field, "log_level") == 0))
		{
			auditLogLevelString = value;
			assign_pgaudit_log_level(auditLogLevelString);
		}
	}
	/* Validation for rule section */
	else if (audit_parse_state == AUDIT_SECTION_RULE)
	{
		int i;

		if ((pg_strcasecmp(field, "format") == 0))
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
						ereport(ERROR,
								(errcode(ERRCODE_CONFIG_FILE_ERROR),
								 errmsg("invalid format parameter \"%s\" of field \"%s\" in rule section",
										value, field)));
					}

					list_len = list_length(value_list);

					/* STRING rule type */
					if (rule->type == AUDIT_RULE_TYPE_STRING)
					{
						char **str_values;
						int i;

						/* Check duplicate setting */
						if (rule->nval > 0)
						{
							AUDIT_ELOG(LOG,
									   "detect duplicate field setting \"%s\"in rule section, overwritten by \"%s\"",
									   field, value);

							/* Reset previous setting */
							for (i = 0; i < rule->nval; i++)
								pfree(((char **)(rule->values))[i]);
							pfree(rule->values);
							rule->nval = 0;
						}

						/* initialize */
						str_values = palloc(sizeof(char *) * list_len);
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
					/* BITMAP rule type */
					else if (rule->type == AUDIT_RULE_TYPE_BITMAP)
					{
						int *bitmap;

						/* Check duplicate setting */
						if (rule->nval > 0)
						{
							AUDIT_ELOG(LOG,
									   "detect duplicate field setting \"%s\"in rule section, overwritten by \"%s\"",
									   field, value);

							/* Reset previous setting */
							pfree(rule->values);
							rule->nval = 0;
						}

						bitmap = (int *) palloc(sizeof(int));
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
								*bitmap |= objecttype_to_bitmap(val, true);
						}

						/*
						 * For bitmap type, the number of values of rule.values
						 * should be 1 because it's a bitmap.
						 */
						rule->nval = 1;
						rule->values = bitmap;
						rule->eq = op_to_bool(op);
					}
					/* TIMESTAMP rule type */
					else if (rule->type == AUDIT_RULE_TYPE_TIMESTAMP)
					{
						TimeADT *ts_values;

						/* Check duplicate setting */
						if (rule->nval > 0)
						{
							AUDIT_ELOG(LOG,
									   "detect duplicate field setting \"%s\"in rule section, overwritten by \"%s\"",
									   field, value);

							/* Reset previous setting */
							pfree(rule->values);
							rule->nval = 0;
						}

						ts_values = (TimeADT *) palloc(sizeof(TimeADT) * list_len * 2);

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
							TimeADT begin = INVALID_ABSTIME;
							TimeADT end = INVALID_ABSTIME;

							/* The timestamp range should be separated by '-' */
							if (!SplitIdentifierString(range_string, '-', &ts_list))
							{
								ereport(ERROR,
										(errcode(ERRCODE_CONFIG_FILE_ERROR),
										 errmsg("invalid format parameter \"%s\" of field \"%s\" in rule section",
												value, field)));
							}

							/* Check if timestamp field is set by the pair */
							if (list_length(ts_list) != 2)
								ereport(ERROR,
										(errcode(ERRCODE_CONFIG_FILE_ERROR),
										 errmsg("timestamp parameter must be set with pair of the begin and end timestamp : \"%s\"",
												value)));

							/* We expect that the format of each ts_cell is 'HH:MM:SS' */
							foreach(ts_cell, ts_list)
							{
								TimeADT ts = str_to_timestamp((char *)lfirst(ts_cell));

								if (begin == INVALID_ABSTIME)
									begin = ts;
								else if (end == INVALID_ABSTIME)
								{
									bool ret;

									/*
									 * The format checking for timestamp is done by time_in function
									 * when tranforming. Here we check if timestamp range is valid or
									 * not.
									 */
									end = ts;
									ret = DirectFunctionCall2(time_lt,
															  TimeADTGetDatum(begin),
															  TimeADTGetDatum(end));
									if (!ret)
									{
										char *begin_str, *end_str;

										begin_str = (char *) DirectFunctionCall1(time_out, TimeADTGetDatum(begin));
										end_str = (char *) DirectFunctionCall1(time_out, TimeADTGetDatum(end));

										ereport(ERROR,
												(errcode(ERRCODE_CONFIG_FILE_ERROR),
												 errmsg("invalid timestamp parameters, the end timestamp must advance to the begin timestamp: "
														"begin = \"%s\", end = \"%s\"",
														begin_str, end_str)));
									}

									begin = end = INVALID_ABSTIME;
								}

								ts_values[rule->nval] = ts;
								rule->nval++;
							}
						}

						rule->values = ts_values;
						rule->eq = op_to_bool(op);
					}
					else
						ereport(ERROR,
								(errcode(ERRCODE_WRONG_OBJECT_TYPE),
								 errmsg("invalid rule type \"%d\"", rule->type)));
					break;
				} /* found corresponding rule */
			} /* loop for rules_template */
		}
	}
	else
	{
		/* XXX : error */
	}
}

#include "pgaudit_scan.c"
