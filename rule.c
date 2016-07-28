/*
 * rule.c
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 */

#include "postgres.h"
#include "miscadmin.h"
#include "libpq/auth.h"

#include "config.h"

static bool apply_one_rule(void *value, AuditRule rule);
static bool apply_string_rule(char *value, AuditRule rule);
static bool apply_integer_rule(int value, AuditRule rule);
static bool apply_timestamp_rule(AuditRule rule);
static bool apply_bitmap_rule(int value, AuditRule rule);

/* Classify the statement using log stmt level and the command tag */
char *
classify_statement_class(AuditEventStackItem *stackItem, int *class)
{
	/* By default, put everything in the MISC class. */
	char *className = CLASS_MISC;
	*class = LOG_MISC;

    switch (stackItem->auditEvent.logStmtLevel)
    {
            /* All mods go in WRITE class, except EXECUTE */
        case LOGSTMT_MOD:
            className = CLASS_WRITE;
            *class = LOG_WRITE;

            switch (stackItem->auditEvent.commandTag)
            {
                    /* Currently, only EXECUTE is different */
                case T_ExecuteStmt:
                    className = CLASS_MISC;
                    *class = LOG_MISC;
                    break;
                default:
                    break;
            }
            break;

            /* These are DDL, unless they are ROLE */
        case LOGSTMT_DDL:
            className = CLASS_DDL;
            *class = LOG_DDL;

            /* Identify role statements */
            switch (stackItem->auditEvent.commandTag)
            {
                /* In the case of create and alter role redact all text in the
                 * command after the password token for security.  This doesn't
                 * cover all possible cases where passwords can be leaked but
                 * should take care of the most common usage.
                 */
                case T_CreateRoleStmt:
                case T_AlterRoleStmt:

                    if (stackItem->auditEvent.commandText != NULL)
                    {
                        char *commandStr;
                        char *passwordToken;
                        int i;
                        int passwordPos;

                        /* Copy the command string and convert to lower case */
                        commandStr = pstrdup(stackItem->auditEvent.commandText);

                        for (i = 0; commandStr[i]; i++)
                            commandStr[i] =
                                (char)pg_tolower((unsigned char)commandStr[i]);

                        /* Find index of password token */
                        passwordToken = strstr(commandStr, TOKEN_PASSWORD);

                        if (passwordToken != NULL)
                        {
                            /* Copy command string up to password token */
                            passwordPos = (passwordToken - commandStr) +
                                          strlen(TOKEN_PASSWORD);

                            commandStr = palloc(passwordPos + 1 +
                                                strlen(TOKEN_REDACTED) + 1);

                            strncpy(commandStr,
                                    stackItem->auditEvent.commandText,
                                    passwordPos);

                            /* And append redacted token */
                            commandStr[passwordPos] = ' ';

                            strcpy(commandStr + passwordPos + 1, TOKEN_REDACTED);

                            /* Assign new command string */
                            stackItem->auditEvent.commandText = commandStr;
                        }
                    }

                /* Classify role statements */
                case T_GrantStmt:
                case T_GrantRoleStmt:
                case T_DropRoleStmt:
                case T_AlterRoleSetStmt:
                case T_AlterDefaultPrivilegesStmt:
                    className = CLASS_ROLE;
                    *class = LOG_ROLE;
                    break;

                    /*
                     * Rename and Drop are general and therefore we have to do
                     * an additional check against the command string to see
                     * if they are role or regular DDL.
                     */
                case T_RenameStmt:
                case T_DropStmt:
                    if (pg_strcasecmp(stackItem->auditEvent.command,
                                      COMMAND_ALTER_ROLE) == 0 ||
                        pg_strcasecmp(stackItem->auditEvent.command,
                                      COMMAND_DROP_ROLE) == 0)
                    {
                        className = CLASS_ROLE;
                        *class = LOG_ROLE;
                    }
                    break;

                default:
                    break;
            }
            break;

            /* Classify the rest */
        case LOGSTMT_ALL:
            switch (stackItem->auditEvent.commandTag)
            {
                    /* READ statements */
                case T_CopyStmt:
                case T_SelectStmt:
                case T_PrepareStmt:
                case T_PlannedStmt:
                    className = CLASS_READ;
                    *class = LOG_READ;
                    break;

                    /* FUNCTION statements */
                case T_DoStmt:
                    className = CLASS_FUNCTION;
                    *class = LOG_FUNCTION;
                    break;

                default:
                    break;
            }
            break;

        case LOGSTMT_NONE:
            break;
    }

	return className;
}

/* Classify the edata using log message */
char *
classify_edata_class(ErrorData *edata, int *class)
{
	char *className = NULL;
	*class = LOG_NONE;

	/* Connection receive, authenticate and disconnection */
	if (strstr(edata->message, AUDIT_MSG_CONNECTION_RECV) ||
		strstr(edata->message, AUDIT_MSG_CONNECTION_AUTH) ||
		strstr(edata->message, AUDIT_MSG_DISCONNECTION))
	{
		*class = LOG_CONNECT;
		className = CLASS_CONNECT;
	}
	/* Shutdown, interrupt, ready to accept connection and new timeline ID */
	else if (strstr(edata->message, AUDIT_MSG_SHUTDOWN) ||
			 strstr(edata->message, AUDIT_MSG_SHUTDOWN_IN_RECOV) ||
			 strstr(edata->message, AUDIT_MSG_INTERRUPT) ||
			 strstr(edata->message, AUDIT_MSG_CONNECTION_READY) ||
			 strstr(edata->message, AUDIT_MSG_NEW_TLID))
	{
		*class = LOG_SYSTEM;
		className = CLASS_SYSTEM;
	}
	/* Replication command for basebackup */
	else if (strstr(edata->message, AUDIT_MSG_REPLICATION))
	{
		*class = LOG_BACKUP;
		className = CLASS_SYSTEM;
	}
	/*
	 * SQL error having '00' prefix error ERRCODE_SUCCESSFUL_COMPLETION
	 * meaning SQL error like syntax error
	 */
	else if (strncmp(unpack_sql_state(edata->sqlerrcode), "00", 2))
	{
		*class = LOG_ERROR;
		className = CLASS_ERROR;
	}

	return className;
}

/*
 * Check if this audit event should be logged by validating
 * configured rules. Return true if this stackItem matched to
 * any rule which means we should log this event, otherwise
 * return false.  Also, we return array of bool that represent
 * index of valid rule for this event.
 *
 * We can fetch the information used by applying rule from
 * stackItem, MyProcPort and other except for class and className.
 *
 * Note that we can use either *stackItem or *edata. If one is
 * valid, another is NULL.
 */
bool
apply_all_rules(AuditEventStackItem *stackItem, ErrorData *edata,
				int class, char *className, bool *valid_rules)
{
	ListCell *cell;
	int index = 0;
	bool matched = false;

	char *database_name = NULL;

	if (stackItem != NULL)
	{
		/* XXX : Prepare information for session "statement" logging */
		database_name = MyProcPort->database_name;
	}
	else
	{
		/* XXX : prepare information for session "edata" logging */
	}

	/*
	 * Validate each rule to this audit event and set true
	 * corresponding index of rule if rules did match.
	 *
	 * XXX : We only support 'database' rule so far. The apply_one_rule
	 * for other rules always return true.
	 */
	foreach(cell, ruleConfigs)
	{
		AuditRuleConfig *rconf = (AuditRuleConfig *)lfirst(cell);
		bool ret = false;

		if (apply_one_rule(NULL, rconf->rules[AUDIT_RULE_TIMESTAMP]) &&
			apply_one_rule(database_name, rconf->rules[AUDIT_RULE_DATABASE]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_CURRENT_USER]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_USER]) &&
			apply_one_rule(&class, rconf->rules[AUDIT_RULE_CLASS]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_COMMAND_TAG]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_OBJECT_TYPE]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_OBJECT_ID]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_APPLICATION_NAME]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_REMOTE_HOST]) &&
			apply_one_rule(NULL, rconf->rules[AUDIT_RULE_REMOTE_PORT]))
		{
			matched = true;
			ret = true;
		}

		/*
		 * Set true to corresponding index iff all apply_XXX method
		 * returned true.
		 */
		valid_rules[index++] = ret;
	}

	return matched;
}

/*
 * Apply given one rule to value, and return true if we determine to
 * log, otherwise return false.
 */
static bool
apply_one_rule(void *value, AuditRule rule)
{
	if (value == NULL)
		return true;

	if (isIntRule(rule))
	{
		int *val = (int *)value;
		return apply_integer_rule(*val, rule);
	}
	else if (isStringRule(rule))
	{
		char *val = (char *)value;
		return apply_string_rule(val, rule);
	}
	else if (isTimestampRule(rule))
		return apply_timestamp_rule(rule);
	else if (isBitmapRule(rule))
	{
		int *val = (int *)value;
		return apply_bitmap_rule(*val, rule);
	}

	return false;
}

/*
 * Check if given string value is listed in rule.values.
 */
static bool
apply_string_rule(char *value, AuditRule rule)
{
	int i;
	char **string_list = (char **) rule.values;

	/* Return ture if this rule was not defined */
	if (rule.values == NULL)
		return true;

	/*
	 * Return true if rule.value has the string same as
	 * value at least 1, otherwise return false.
	 */
	for (i = 0; i < rule.nval; i++)
	{
		if (pg_strcasecmp(value, string_list[i]) == 0)
			return true;
	}

	return false;
}

static bool
apply_integer_rule(int value, AuditRule rule)
{
	/* XXX : we should complete this function */
	return true;
}

/*
 * Check if current timestamp is within the range of rule.
 */
static bool
apply_timestamp_rule(AuditRule rule)
{
	/* XXX : we should complete this function */
	return true;
}

/*
 * Check if given value is within bitmap of rule.
 */
static bool
apply_bitmap_rule(int value, AuditRule rule)
{
	/* XXX : we should complete this function */
	return true;
}
