/*------------------------------------------------------------------------------
 * pgaudit.c
 *
 * An audit logging extension for PostgreSQL. Provides detailed logging classes,
 * object level logging, and fully-qualified object names for all DML and DDL
 * statements where possible (See pgaudit.sgml for details).
 *
 * Copyright (c) 2014-2015, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *          pgaudit/pgaudit.c
 *------------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/namespace.h"
#include "commands/dbcommands.h"
#include "catalog/pg_proc.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "nodes/nodes.h"
#include "tcop/utility.h"
#include "tcop/deparse_utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

#include "pgaudit.h"
#include "config.h"

PG_MODULE_MAGIC;

void _PG_init(void);

PG_FUNCTION_INFO_V1(pgaudit_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_sql_drop);

/*
 * GUC variable for pgaudit.config_file
 *
 * Administrators can specify the path to the configuration file.
 */
char *config_file = NULL;

/*
 * Audit type, which is responsbile for the log message
 */
#define AUDIT_TYPE_OBJECT   "OBJECT"
#define AUDIT_TYPE_SESSION  "SESSION"

/*
 * Command, used for SELECT/DML and function calls.
 *
 * We hook into the executor, but we do not have access to the parsetree there.
 * Therefore we can't simply call CreateCommandTag() to get the command and have
 * to build it ourselves based on what information we do have.
 *
 * These should be updated if new commands are added to what the exectuor
 * currently handles.  Note that most of the interesting commands do not go
 * through the executor but rather ProcessUtility, where we have the parsetree.
 */
#define COMMAND_SELECT      "SELECT"
#define COMMAND_INSERT      "INSERT"
#define COMMAND_UPDATE      "UPDATE"
#define COMMAND_DELETE      "DELETE"
#define COMMAND_EXECUTE     "EXECUTE"
#define COMMAND_UNKNOWN     "UNKNOWN"

/*
 * AUDIT_ELOG() is for audit logging differ to ereport. Now that we emit the audit
 * log in  pgaudit_emit_log_hook, it's possible to emit the log recusively. To
 * prevent it, we introduece a variable emitAuditLogCalled, which is 0 by default.
 * > 1 means that we alreadby emited some logs, so we don't need to emit log anymore.
 *
 * In case where we want to use elog/ereport, we should use AUDIT_ELOG/EREPORT instead
 *  which easily avoid to emit log recusively.
 */
static int emitAuditLogCalled = 0;
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

AuditEventStackItem *auditEventStack = NULL;

/* Function prototype for hook */
static void pgaudit_emit_log_hook(ErrorData *edata);

static void append_valid_csv(StringInfoData *buffer, const char *appendStr);
static void emit_session_sql_log(AuditEventStackItem *stackItem, bool *valid_rules,
								   const char *className);

/*
 * Hook functions
 */
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorStart_hook_type next_ExecutorStart_hook = NULL;
static emit_log_hook_type next_emit_log_hook = NULL;

/*
 * pgAudit runs queries of its own when using the event trigger system.
 *
 * Track when we are running a query and don't log it.
 */
static bool internalStatement = false;

/*
 * Track running total for statements and substatements and whether or not
 * anything has been logged since the current statement began.
 */
static int64 statementTotal = 0;
static int64 substatementTotal = 0;
static int64 stackTotal = 0;

static bool statementLogged = false;

/*
 * Emit the SESSION log for event from emit_log_hook. This routine is
 * used for logging of connection, disconnection, replication command etc.
 */
static void
pgaudit_emit_log_hook(ErrorData *edata)
{
	int class;
	char *className = NULL;
	bool *valid_rules = palloc(sizeof(bool) * list_length(ruleConfigs));

	if (emitAuditLogCalled == 0)
	{
		/* Get class and className using edata */
		className = classify_edata_class(edata, &class);

		/* If we are not interested in this message, skip routine */
		if (className != NULL)
		{
			/*
			 * Only log the statement if the edata matches to all rules of
			 * multiple rule secion.
			 */
			if (!apply_all_rules(NULL, edata, class, className, valid_rules))
				return;

			/*
			 * XXX : We should separate function for emitting log to common
			 * function with log_audit_event.
			 */
			AUDIT_EREPORT(auditLogLevel,
					(errmsg("AUDIT: SESSION,%s,%s",
							className,
							edata->message),
					 errhidestmt(true),
					 errhidecontext(true)));
		}
	}

	if (next_emit_log_hook)
		(*next_emit_log_hook) (edata);
}

/*
 * Emit the SESSION log for stackItem. The caller must set appropriate
 * memory context and back it after finished.
 */
static void
emit_session_sql_log(AuditEventStackItem *stackItem, bool *valid_rules,
					 const char *className)
{
	StringInfoData auditStr;
	ListCell *cell;
	int num = 0;

	foreach(cell, ruleConfigs)
	{
		//AuditRuleConfig *rconf = lfirst(cell); /* used for format */

		/* If this event does not match to current rule, ignore it */
		if (!valid_rules[num])
		{
			num++;
			continue;
		}

		initStringInfo(&auditStr);
		append_valid_csv(&auditStr, stackItem->auditEvent.command);

		appendStringInfoCharMacro(&auditStr, ',');
		append_valid_csv(&auditStr, stackItem->auditEvent.objectType);

		appendStringInfoCharMacro(&auditStr, ',');
		append_valid_csv(&auditStr, stackItem->auditEvent.objectName);

		if (!stackItem->auditEvent.statementLogged || !auditLogStatementOnce)
		{
			append_valid_csv(&auditStr, stackItem->auditEvent.commandText);

			appendStringInfoCharMacro(&auditStr, ',');

			/* Handle parameter logging, if enabled. */
			if (auditLogParameter)
			{
				int paramIdx;
				int numParams;
				StringInfoData paramStrResult;
				ParamListInfo paramList = stackItem->auditEvent.paramList;

				numParams = paramList == NULL ? 0 : paramList->numParams;

				/* Create the param substring */
				initStringInfo(&paramStrResult);

				/* Iterate through all params */
				for (paramIdx = 0; paramList != NULL && paramIdx < numParams;
					 paramIdx++)
				{
					ParamExternData *prm = &paramList->params[paramIdx];
					Oid typeOutput;
					bool typeIsVarLena;
					char *paramStr;

					/* Add a comma for each param */
					if (paramIdx != 0)
						appendStringInfoCharMacro(&paramStrResult, ',');

					/* Skip if null or if oid is invalid */
					if (prm->isnull || !OidIsValid(prm->ptype))
						continue;

					/* Output the string */
					getTypeOutputInfo(prm->ptype, &typeOutput, &typeIsVarLena);
					paramStr = OidOutputFunctionCall(typeOutput, prm->value);

					append_valid_csv(&paramStrResult, paramStr);
					pfree(paramStr);
				}

				if (numParams == 0)
					appendStringInfoString(&auditStr, "<none>");
				else
					append_valid_csv(&auditStr, paramStrResult.data);
			}
			else
				appendStringInfoString(&auditStr, "<not logged>");

			stackItem->auditEvent.statementLogged = true;
		}
		else
			/* we were asked to not log it */
			appendStringInfoString(&auditStr,
								   "<previously logged>,<previously logged>");

		ereport(auditLogLevel,
				(errmsg("AUDIT: SESSION," INT64_FORMAT "," INT64_FORMAT ",%s,%s",
						stackItem->auditEvent.statementId,
						stackItem->auditEvent.substatementId,
						className,
						auditStr.data),
				 errhidestmt(true),
				 errhidecontext(true)));

		stackItem->auditEvent.logged = true;
	}

}

/* Debug functio which will be removed */
static void
print_config(void)
{
	ListCell *cell;

	fprintf(stderr, "log_catalog = %d\n", auditLogCatalog);
	fprintf(stderr, "log_level_string = %s\n", auditLogLevelString);
	fprintf(stderr, "log_level = %d\n", auditLogLevel);
	fprintf(stderr, "log_parameter = %d\n", auditLogParameter);
	fprintf(stderr, "log_relation = %d\n", auditLogRelation);
	fprintf(stderr, "log_statement_once = %d\n", auditLogStatementOnce);
	fprintf(stderr, "role = %s\n", auditRole);
	fprintf(stderr, "logger = %s\n", outputConfig->logger);
	fprintf(stderr, "facility = %s\n", outputConfig->facility);
	fprintf(stderr, "priority = %s\n", outputConfig->priority);
	fprintf(stderr, "ident = %s\n", outputConfig->ident);
	fprintf(stderr, "option = %s\n", outputConfig->option);
	fprintf(stderr, "pathlog = %s\n", outputConfig->pathlog);

	foreach(cell, ruleConfigs)
	{
		AuditRuleConfig *rconf = lfirst(cell);
		int j;
		fprintf(stderr, "Format = %s\n", rconf->format);

		for (j = 0; j < AUDIT_NUM_RULES; j++)
		{
			AuditRule rule = rconf->rules[j];

			if (rule.values == NULL)
				continue;

			if (isIntRule(rule))
			{
				int num = rule.nval;
				int i;

				for (i = 0; i < num; i++)
				{
					int val = ((int *)rule.values)[i];
					fprintf(stderr, "    INT %s %s %d\n",
							rule.field,
							rule.eq ? "=" : "!=",
							val);
				}
			}
			else if (isStringRule(rule))
			{
				int num = rule.nval;
				int i;

				for (i = 0; i < num; i++)
				{
					char *val = ((char **)rule.values)[i];
					fprintf(stderr, "    STR %s %s %s\n",
							rule.field,
							rule.eq ? "=" : "!=",
							val);
				}
			}
			else if (isBitmapRule(rule))
			{
				int val = *((int *)rule.values);

				fprintf(stderr, "    BMP %s %s %d\n",
						rule.field,
						rule.eq ? "=" : "!=",
						val);
			}
			else
			{
				int num = rule.nval;
				int i;
				for (i = 0; i < num; i++)
				{
					pg_time_t val = ((pg_time_t *)rule.values)[i];
					fprintf(stderr, "    TMS %s %s %ld\n",
							rule.field,
							rule.eq ? "=" : "!=",
							val);
				}
			}
		}
	}
}

/*
 * Stack functions
 *
 * Audit events can go down to multiple levels so a stack is maintained to keep
 * track of them.
 */

/*
 * Respond to callbacks registered with MemoryContextRegisterResetCallback().
 * Removes the event(s) off the stack that have become obsolete once the
 * MemoryContext has been freed.  The callback should always be freeing the top
 * of the stack, but the code is tolerant of out-of-order callbacks.
 */
static void
stack_free(void *stackFree)
{
    AuditEventStackItem *nextItem = auditEventStack;

    /* Only process if the stack contains items */
    while (nextItem != NULL)
    {
        /* Check if this item matches the item to be freed */
        if (nextItem == (AuditEventStackItem *) stackFree)
        {
            /* Move top of stack to the item after the freed item */
            auditEventStack = nextItem->next;

            /* If the stack is not empty */
            if (auditEventStack == NULL)
            {
                /*
                 * Reset internal statement to false.  Normally this will be
                 * reset but in case of an error it might be left set.
                 */
                internalStatement = false;

                /*
                 * Reset sub statement total so the next statement will start
                 * from 1.
                 */
                substatementTotal = 0;

                /*
                 * Reset statement logged so that next statement will be
                 * logged.
                 */
                statementLogged = false;
            }

            return;
        }

        nextItem = nextItem->next;
    }
}

/*
 * Push a new audit event onto the stack and create a new memory context to
 * store it.
 */
static AuditEventStackItem *
stack_push()
{
    MemoryContext contextAudit;
    MemoryContext contextOld;
    AuditEventStackItem *stackItem;

    /*
     * Create a new memory context to contain the stack item.  This will be
     * free'd on stack_pop, or by our callback when the parent context is
     * destroyed.
     */
    contextAudit = AllocSetContextCreate(CurrentMemoryContext,
                                         "pgaudit stack context",
                                         ALLOCSET_DEFAULT_MINSIZE,
                                         ALLOCSET_DEFAULT_INITSIZE,
                                         ALLOCSET_DEFAULT_MAXSIZE);

    /* Save the old context to switch back to at the end */
    contextOld = MemoryContextSwitchTo(contextAudit);

    /* Create our new stack item in our context */
    stackItem = palloc0(sizeof(AuditEventStackItem));
    stackItem->contextAudit = contextAudit;
    stackItem->stackId = ++stackTotal;

    /*
     * Setup a callback in case an error happens.  stack_free() will truncate
     * the stack at this item.
     */
    stackItem->contextCallback.func = stack_free;
    stackItem->contextCallback.arg = (void *) stackItem;
    MemoryContextRegisterResetCallback(contextAudit,
                                       &stackItem->contextCallback);

    /* Push new item onto the stack */
    if (auditEventStack != NULL)
        stackItem->next = auditEventStack;
    else
        stackItem->next = NULL;

    auditEventStack = stackItem;

    MemoryContextSwitchTo(contextOld);

    return stackItem;
}

/*
 * Pop an audit event from the stack by deleting the memory context that
 * contains it.  The callback to stack_free() does the actual pop.
 */
static void
stack_pop(int64 stackId)
{
    /* Make sure what we want to delete is at the top of the stack */
    if (auditEventStack != NULL && auditEventStack->stackId == stackId)
        MemoryContextDelete(auditEventStack->contextAudit);
    else
        elog(ERROR, "pgaudit stack item " INT64_FORMAT " not found on top - cannot pop",
             stackId);
}

/*
 * Check that an item is on the stack.  If not, an error will be raised since
 * this is a bad state to be in and it might mean audit records are being lost.
 */
static void
stack_valid(int64 stackId)
{
    AuditEventStackItem *nextItem = auditEventStack;

    /* Look through the stack for the stack entry */
    while (nextItem != NULL && nextItem->stackId != stackId)
        nextItem = nextItem->next;

    /* If we didn't find it, something went wrong. */
    if (nextItem == NULL)
        elog(ERROR, "pgaudit stack item " INT64_FORMAT
             " not found - top of stack is " INT64_FORMAT "",
             stackId,
             auditEventStack == NULL ? (int64) -1 : auditEventStack->stackId);
}

/*
 * Appends a properly quoted CSV field to StringInfo.
 */
static void
append_valid_csv(StringInfoData *buffer, const char *appendStr)
{
    const char *pChar;

    /*
     * If the append string is null then do nothing.  NULL fields are not
     * quoted in CSV.
     */
    if (appendStr == NULL)
        return;

    /* Only format for CSV if appendStr contains: ", comma, \n, \r */
    if (strstr(appendStr, ",") || strstr(appendStr, "\"") ||
        strstr(appendStr, "\n") || strstr(appendStr, "\r"))
    {
        appendStringInfoCharMacro(buffer, '"');

        for (pChar = appendStr; *pChar; pChar++)
        {
            if (*pChar == '"')    /* double single quotes */
                appendStringInfoCharMacro(buffer, *pChar);

            appendStringInfoCharMacro(buffer, *pChar);
        }

        appendStringInfoCharMacro(buffer, '"');
    }
    /* Else just append */
    else
        appendStringInfoString(buffer, appendStr);
}

/*
 * Takes an AuditEvent, classifies it, then logs it if appropriate.
 *
 * Logging is decided based on if the statement is in one of the classes being
 * logged or if an object used has been marked for auditing.
 *
 * Objects are marked for auditing by the auditor role being granted access
 * to the object.  The kind of access (INSERT, UPDATE, etc) is also considered
 * and logging is only performed when the kind of access matches the granted
 * right on the object.
 *
 * This will need to be updated if new kinds of GRANTs are added.
 */
static void
log_audit_event(AuditEventStackItem *stackItem)
{
    /* By default, put everything in the MISC class. */
    char *className = CLASS_MISC;
	int class;
    MemoryContext contextOld;
    StringInfoData auditStr;
	bool *valid_rules;

    /* If this event has already been logged don't log it again */
    if (stackItem->auditEvent.logged)
        return;

	valid_rules = palloc(sizeof(bool) * list_length(ruleConfigs));

	/* Get class and className using stackItem */
	className = classify_statement_class(stackItem, &class);

	/*----------
     * Only log the statement if:
     *
     * 1. If object was selected for audit logging (granted), or
     * 2. The statement matches to all rules of multiple rule sections.
     *
     * If neither of these is true, return.
     *----------
     */
	/*
	 * XXX : Here, we have to do check if auditEven can be machted with
	 * any rules we defined. Return from here if not matched to any rules.
	 */
	if (!stackItem->auditEvent.granted &&
		!apply_all_rules(stackItem, NULL, class, className, valid_rules))
		return ;

    /*
     * Use audit memory context in case something is not free'd while
     * appending strings and parameters.
     */
    contextOld = MemoryContextSwitchTo(stackItem->contextAudit);

    /* Set statement and substatement IDs */
    if (stackItem->auditEvent.statementId == 0)
    {
        /* If nothing has been logged yet then create a new statement Id */
        if (!statementLogged)
        {
            statementTotal++;
            statementLogged = true;
        }

        stackItem->auditEvent.statementId = statementTotal;
        stackItem->auditEvent.substatementId = ++substatementTotal;
    }

	/*
	 * If we are going to emit the SESSION log, granted is set false.
	 * In this case, we emit the log according to defined rules
	 */
	if (stackItem->auditEvent.granted == false)
	{
		emit_session_sql_log(stackItem, valid_rules, className);
		MemoryContextSwitchTo(contextOld);
		return;
	}

    /*
     * Create the audit substring
     *
     * The type-of-audit-log and statement/substatement ID are handled below,
     * this string is everything else.
     */
    initStringInfo(&auditStr);
    append_valid_csv(&auditStr, stackItem->auditEvent.command);

    appendStringInfoCharMacro(&auditStr, ',');
    append_valid_csv(&auditStr, stackItem->auditEvent.objectType);

    appendStringInfoCharMacro(&auditStr, ',');
    append_valid_csv(&auditStr, stackItem->auditEvent.objectName);

    /*
     * If auditLogStatmentOnce is true, then only log the statement and
     * parameters if they have not already been logged for this substatement.
     */
    appendStringInfoCharMacro(&auditStr, ',');
    if (!stackItem->auditEvent.statementLogged || !auditLogStatementOnce)
    {
        append_valid_csv(&auditStr, stackItem->auditEvent.commandText);

        appendStringInfoCharMacro(&auditStr, ',');

        /* Handle parameter logging, if enabled. */
        if (auditLogParameter)
        {
            int paramIdx;
            int numParams;
            StringInfoData paramStrResult;
            ParamListInfo paramList = stackItem->auditEvent.paramList;

            numParams = paramList == NULL ? 0 : paramList->numParams;

            /* Create the param substring */
            initStringInfo(&paramStrResult);

            /* Iterate through all params */
            for (paramIdx = 0; paramList != NULL && paramIdx < numParams;
                 paramIdx++)
            {
                ParamExternData *prm = &paramList->params[paramIdx];
                Oid typeOutput;
                bool typeIsVarLena;
                char *paramStr;

                /* Add a comma for each param */
                if (paramIdx != 0)
                    appendStringInfoCharMacro(&paramStrResult, ',');

                /* Skip if null or if oid is invalid */
                if (prm->isnull || !OidIsValid(prm->ptype))
                    continue;

                /* Output the string */
                getTypeOutputInfo(prm->ptype, &typeOutput, &typeIsVarLena);
                paramStr = OidOutputFunctionCall(typeOutput, prm->value);

                append_valid_csv(&paramStrResult, paramStr);
                pfree(paramStr);
            }

            if (numParams == 0)
                appendStringInfoString(&auditStr, "<none>");
            else
                append_valid_csv(&auditStr, paramStrResult.data);
        }
        else
            appendStringInfoString(&auditStr, "<not logged>");

        stackItem->auditEvent.statementLogged = true;
    }
    else
        /* we were asked to not log it */
        appendStringInfoString(&auditStr,
                               "<previously logged>,<previously logged>");

    /*
     * Log the audit entry.  Note: use of INT64_FORMAT here is bad for
     * translatability, but we currently haven't got translation support in
     * pgaudit anyway.
     */
    ereport(auditLogLevel,
            (errmsg("AUDIT: OBJECT," INT64_FORMAT "," INT64_FORMAT ",%s,%s",
                    stackItem->auditEvent.statementId,
                    stackItem->auditEvent.substatementId,
                    className,
                    auditStr.data),
                    errhidestmt(true),
                    errhidecontext(true)));

    stackItem->auditEvent.logged = true;

    MemoryContextSwitchTo(contextOld);
}

/*
 * Check if the role or any inherited role has any permission in the mask.  The
 * public role is excluded from this check and superuser permissions are not
 * considered.
 */
static bool
audit_on_acl(Datum aclDatum,
             Oid auditOid,
             AclMode mask)
{
    bool result = false;
    Acl *acl;
    AclItem *aclItemData;
    int aclIndex;
    int aclTotal;

    /* Detoast column's ACL if necessary */
    acl = DatumGetAclP(aclDatum);

    /* Get the acl list and total number of items */
    aclTotal = ACL_NUM(acl);
    aclItemData = ACL_DAT(acl);

    /* Check privileges granted directly to auditOid */
    for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
    {
        AclItem *aclItem = &aclItemData[aclIndex];

        if (aclItem->ai_grantee == auditOid &&
            aclItem->ai_privs & mask)
        {
            result = true;
            break;
        }
    }

    /*
     * Check privileges granted indirectly via role memberships. We do this in
     * a separate pass to minimize expensive indirect membership tests.  In
     * particular, it's worth testing whether a given ACL entry grants any
     * privileges still of interest before we perform the has_privs_of_role
     * test.
     */
    if (!result)
    {
        for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
        {
            AclItem *aclItem = &aclItemData[aclIndex];

            /* Don't test public or auditOid (it has been tested already) */
            if (aclItem->ai_grantee == ACL_ID_PUBLIC ||
                aclItem->ai_grantee == auditOid)
                continue;

            /*
             * Check that the role has the required privileges and that it is
             * inherited by auditOid.
             */
            if (aclItem->ai_privs & mask &&
                has_privs_of_role(auditOid, aclItem->ai_grantee))
            {
                result = true;
                break;
            }
        }
    }

    /* if we have a detoasted copy, free it */
    if (acl && (Pointer) acl != DatumGetPointer(aclDatum))
        pfree(acl);

    return result;
}

/*
 * Check if a role has any of the permissions in the mask on a relation.
 */
static bool
audit_on_relation(Oid relOid,
                  Oid auditOid,
                  AclMode mask)
{
    bool result = false;
    HeapTuple tuple;
    Datum aclDatum;
    bool isNull;

    /* Get relation tuple from pg_class */
    tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
    if (!HeapTupleIsValid(tuple))
        return false;

    /* Get the relation's ACL */
    aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl,
                               &isNull);

    /* Only check if non-NULL, since NULL means no permissions */
    if (!isNull)
        result = audit_on_acl(aclDatum, auditOid, mask);

    /* Free the relation tuple */
    ReleaseSysCache(tuple);

    return result;
}

/*
 * Check if a role has any of the permissions in the mask on a column.
 */
static bool
audit_on_attribute(Oid relOid,
                   AttrNumber attNum,
                   Oid auditOid,
                   AclMode mask)
{
    bool result = false;
    HeapTuple attTuple;
    Datum aclDatum;
    bool isNull;

    /* Get the attribute's ACL */
    attTuple = SearchSysCache2(ATTNUM,
                               ObjectIdGetDatum(relOid),
                               Int16GetDatum(attNum));
    if (!HeapTupleIsValid(attTuple))
        return false;

    /* Only consider attributes that have not been dropped */
    if (!((Form_pg_attribute) GETSTRUCT(attTuple))->attisdropped)
    {
        aclDatum = SysCacheGetAttr(ATTNUM, attTuple, Anum_pg_attribute_attacl,
                                   &isNull);

        if (!isNull)
            result = audit_on_acl(aclDatum, auditOid, mask);
    }

    /* Free attribute */
    ReleaseSysCache(attTuple);

    return result;
}

/*
 * Check if a role has any of the permissions in the mask on a column in
 * the provided set.  If the set is empty, then all valid columns in the
 * relation will be tested.
 */
static bool
audit_on_any_attribute(Oid relOid,
                       Oid auditOid,
                       Bitmapset *attributeSet,
                       AclMode mode)
{
    bool result = false;
    AttrNumber col;
    Bitmapset *tmpSet;

    /* If bms is empty then check for any column match */
    if (bms_is_empty(attributeSet))
    {
        HeapTuple classTuple;
        AttrNumber nattrs;
        AttrNumber curr_att;

        /* Get relation to determine total columns */
        classTuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));

        if (!HeapTupleIsValid(classTuple))
            return false;

        nattrs = ((Form_pg_class) GETSTRUCT(classTuple))->relnatts;
        ReleaseSysCache(classTuple);

        /* Check each column */
        for (curr_att = 1; curr_att <= nattrs; curr_att++)
            if (audit_on_attribute(relOid, curr_att, auditOid, mode))
                return true;
    }

    /* bms_first_member is destructive, so make a copy before using it. */
    tmpSet = bms_copy(attributeSet);

    /* Check each column */
    while ((col = bms_first_member(tmpSet)) >= 0)
    {
        col += FirstLowInvalidHeapAttributeNumber;

        if (col != InvalidAttrNumber &&
            audit_on_attribute(relOid, col, auditOid, mode))
        {
            result = true;
            break;
        }
    }

    bms_free(tmpSet);

    return result;
}

/*
 * Create AuditEvents for SELECT/DML operations via executor permissions checks.
 */
static void
log_select_dml(Oid auditOid, List *rangeTabls)
{
    ListCell *lr;
    bool first = true;
    bool found = false;

    /* Do not log if this is an internal statement */
    if (internalStatement)
        return;

    foreach(lr, rangeTabls)
    {
        Oid relOid;
        Relation rel;
        RangeTblEntry *rte = lfirst(lr);

        /* We only care about tables, and can ignore subqueries etc. */
        if (rte->rtekind != RTE_RELATION)
            continue;

        found = true;

        /*
         * Don't log if the session user is not a member of the current
         * role.  This prevents contents of security definer functions
         * from being logged and supresses foreign key queries unless the
         * session user is the owner of the referenced table.
         */
        if (!is_member_of_role(GetSessionUserId(), GetUserId()))
            return;

        /*
         * If we are not logging all-catalog queries (auditLogCatalog is
         * false) then filter out any system relations here.
         */
        relOid = rte->relid;
        rel = relation_open(relOid, NoLock);

        if (!auditLogCatalog && IsSystemNamespace(RelationGetNamespace(rel)))
        {
            relation_close(rel, NoLock);
            continue;
        }

        /*
         * Default is that this was not through a grant, to support session
         * logging.  Will be updated below if a grant is found.
         */
        auditEventStack->auditEvent.granted = false;

        /*
         * If this is the first RTE then session log unless auditLogRelation
         * is set.
         */
        if (first && !auditLogRelation)
        {
            log_audit_event(auditEventStack);

            first = false;
        }

        /*
         * We don't have access to the parsetree here, so we have to generate
         * the node type, object type, and command tag by decoding
         * rte->requiredPerms and rte->relkind.
         */
        if (rte->requiredPerms & ACL_INSERT)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_InsertStmt;
            auditEventStack->auditEvent.command = COMMAND_INSERT;
        }
        else if (rte->requiredPerms & ACL_UPDATE)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_UpdateStmt;
            auditEventStack->auditEvent.command = COMMAND_UPDATE;
        }
        else if (rte->requiredPerms & ACL_DELETE)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
            auditEventStack->auditEvent.commandTag = T_DeleteStmt;
            auditEventStack->auditEvent.command = COMMAND_DELETE;
        }
        else if (rte->requiredPerms & ACL_SELECT)
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
            auditEventStack->auditEvent.commandTag = T_SelectStmt;
            auditEventStack->auditEvent.command = COMMAND_SELECT;
        }
        else
        {
            auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
            auditEventStack->auditEvent.commandTag = T_Invalid;
            auditEventStack->auditEvent.command = COMMAND_UNKNOWN;
        }

        /* Use the relation type to assign object type */
        switch (rte->relkind)
        {
            case RELKIND_RELATION:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_TABLE;
                break;

            case RELKIND_INDEX:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_INDEX;
                break;

            case RELKIND_SEQUENCE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_SEQUENCE;
                break;

            case RELKIND_TOASTVALUE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_TOASTVALUE;
                break;

            case RELKIND_VIEW:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_VIEW;
                break;

            case RELKIND_COMPOSITE_TYPE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_COMPOSITE_TYPE;
                break;

            case RELKIND_FOREIGN_TABLE:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_FOREIGN_TABLE;
                break;

            case RELKIND_MATVIEW:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_MATVIEW;
                break;

            default:
                auditEventStack->auditEvent.objectType = OBJECT_TYPE_UNKNOWN;
                break;
        }

        /* Get a copy of the relation name and assign it to object name */
        auditEventStack->auditEvent.objectName =
            quote_qualified_identifier(get_namespace_name(
                                           RelationGetNamespace(rel)),
                                       RelationGetRelationName(rel));
        relation_close(rel, NoLock);

        /* Perform object auditing only if the audit role is valid */
        if (auditOid != InvalidOid)
        {
            AclMode auditPerms =
                (ACL_SELECT | ACL_UPDATE | ACL_INSERT | ACL_DELETE) &
                rte->requiredPerms;

            /*
             * If any of the required permissions for the relation are granted
             * to the audit role then audit the relation
             */
            if (audit_on_relation(relOid, auditOid, auditPerms))
                auditEventStack->auditEvent.granted = true;

            /*
             * Else check if the audit role has column-level permissions for
             * select, insert, or update.
             */
            else if (auditPerms != 0)
            {
                /*
                 * Check the select columns
                 */
                if (auditPerms & ACL_SELECT)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->selectedCols,
                                               ACL_SELECT);

                /*
                 * Check the insert columns
                 */
                if (!auditEventStack->auditEvent.granted &&
                    auditPerms & ACL_INSERT)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->insertedCols,
                                               auditPerms);

                /*
                 * Check the update columns
                 */
                if (!auditEventStack->auditEvent.granted &&
                    auditPerms & ACL_UPDATE)
                    auditEventStack->auditEvent.granted =
                        audit_on_any_attribute(relOid, auditOid,
                                               rte->updatedCols,
                                               auditPerms);
            }
        }

        /* Do relation level logging if a grant was found */
        if (auditEventStack->auditEvent.granted)
        {
            auditEventStack->auditEvent.logged = false;
            log_audit_event(auditEventStack);
        }

        /* Do relation level logging if auditLogRelation is set */
        if (auditLogRelation)
        {
            auditEventStack->auditEvent.logged = false;
            auditEventStack->auditEvent.granted = false;
            log_audit_event(auditEventStack);
        }

        pfree(auditEventStack->auditEvent.objectName);
    }

    /*
     * If no tables were found that means that RangeTbls was empty or all
     * relations were in the system schema.  In that case still log a session
     * record.
     */
    if (!found)
    {
        auditEventStack->auditEvent.granted = false;
        auditEventStack->auditEvent.logged = false;

        log_audit_event(auditEventStack);
    }
}

/*
 * Create AuditEvents for non-catalog function execution, as detected by
 * log_object_access() below.
 */
static void
log_function_execute(Oid objectId)
{
    HeapTuple proctup;
    Form_pg_proc proc;
    AuditEventStackItem *stackItem;

    /* Get info about the function. */
    proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));

    if (!proctup)
        elog(ERROR, "cache lookup failed for function %u", objectId);

    proc = (Form_pg_proc) GETSTRUCT(proctup);

    /*
     * Logging execution of all pg_catalog functions would make the log
     * unusably noisy.
     */
    if (IsSystemNamespace(proc->pronamespace))
    {
        ReleaseSysCache(proctup);
        return;
    }

    /* Push audit event onto the stack */
    stackItem = stack_push();

    /* Generate the fully-qualified function name. */
    stackItem->auditEvent.objectName =
        quote_qualified_identifier(get_namespace_name(proc->pronamespace),
                                   NameStr(proc->proname));
    ReleaseSysCache(proctup);

    /* Log the function call */
    stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
    stackItem->auditEvent.commandTag = T_DoStmt;
    stackItem->auditEvent.command = COMMAND_EXECUTE;
    stackItem->auditEvent.objectType = OBJECT_TYPE_FUNCTION;
    stackItem->auditEvent.commandText = stackItem->next->auditEvent.commandText;

    log_audit_event(stackItem);

    /* Pop audit event from the stack */
    stack_pop(stackItem->stackId);
}


/*
 * Hook ExecutorStart to get the query text and basic command type for queries
 * that do not contain a table and so can't be idenitified accurately in
 * ExecutorCheckPerms.
 */
static void
pgaudit_ExecutorStart_hook(QueryDesc *queryDesc, int eflags)
{
    AuditEventStackItem *stackItem = NULL;

    if (!internalStatement)
    {
        /* Push the audit even onto the stack */
        stackItem = stack_push();

        /* Initialize command using queryDesc->operation */
        switch (queryDesc->operation)
        {
            case CMD_SELECT:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
                stackItem->auditEvent.commandTag = T_SelectStmt;
                stackItem->auditEvent.command = COMMAND_SELECT;
                break;

            case CMD_INSERT:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_InsertStmt;
                stackItem->auditEvent.command = COMMAND_INSERT;
                break;

            case CMD_UPDATE:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_UpdateStmt;
                stackItem->auditEvent.command = COMMAND_UPDATE;
                break;

            case CMD_DELETE:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
                stackItem->auditEvent.commandTag = T_DeleteStmt;
                stackItem->auditEvent.command = COMMAND_DELETE;
                break;

            default:
                stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
                stackItem->auditEvent.commandTag = T_Invalid;
                stackItem->auditEvent.command = COMMAND_UNKNOWN;
                break;
        }

        /* Initialize the audit event */
        stackItem->auditEvent.commandText = queryDesc->sourceText;
        stackItem->auditEvent.paramList = queryDesc->params;
    }

    /* Call the previous hook or standard function */
    if (next_ExecutorStart_hook)
        next_ExecutorStart_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);

    /*
     * Move the stack memory context to the query memory context.  This needs
     * to be done here because the query context does not exist before the
     * call to standard_ExecutorStart() but the stack item is required by
     * pgaudit_ExecutorCheckPerms_hook() which is called during
     * standard_ExecutorStart().
     */
    if (stackItem)
        MemoryContextSetParent(stackItem->contextAudit,
                               queryDesc->estate->es_query_cxt);
}

/*
 * Hook ExecutorCheckPerms to do session and object auditing for DML.
 */
static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
    Oid auditOid;

    /* Get the audit oid if the role exists */
    auditOid = get_role_oid(auditRole, true);

    /* Log DML if the audit role is valid or session logging is enabled */
    if ((auditOid != InvalidOid || ruleConfigs != NULL) &&
        !IsAbortedTransactionBlockState())
        log_select_dml(auditOid, rangeTabls);

    /* Call the next hook function */
    if (next_ExecutorCheckPerms_hook &&
        !(*next_ExecutorCheckPerms_hook) (rangeTabls, abort))
        return false;

    return true;
}

/*
 * Hook ProcessUtility to do session auditing for DDL and utility commands.
 */
static void
pgaudit_ProcessUtility_hook(Node *parsetree,
                             const char *queryString,
                             ProcessUtilityContext context,
                             ParamListInfo params,
                             DestReceiver *dest,
                             char *completionTag)
{
    AuditEventStackItem *stackItem = NULL;
    int64 stackId = 0;

    /*
     * Don't audit substatements.  All the substatements we care about should
     * be covered by the event triggers.
     */
    if (context <= PROCESS_UTILITY_QUERY && !IsAbortedTransactionBlockState())
    {
        /* Process top level utility statement */
        if (context == PROCESS_UTILITY_TOPLEVEL)
        {
            if (auditEventStack != NULL)
                elog(ERROR, "pgaudit stack is not empty");

            stackItem = stack_push();
            stackItem->auditEvent.paramList = params;
        }
        else
            stackItem = stack_push();

        stackId = stackItem->stackId;
        stackItem->auditEvent.logStmtLevel = GetCommandLogLevel(parsetree);
        stackItem->auditEvent.commandTag = nodeTag(parsetree);
        stackItem->auditEvent.command = CreateCommandTag(parsetree);
        stackItem->auditEvent.commandText = queryString;

        /*
         * If this is a DO block log it before calling the next ProcessUtility
         * hook.
         */
        if (stackItem->auditEvent.commandTag == T_DoStmt &&
            !IsAbortedTransactionBlockState())
            log_audit_event(stackItem);
    }

    /* Call the standard process utility chain. */
    if (next_ProcessUtility_hook)
        (*next_ProcessUtility_hook) (parsetree, queryString, context,
                                     params, dest, completionTag);
    else
        standard_ProcessUtility(parsetree, queryString, context,
                                params, dest, completionTag);

    /*
     * Process the audit event if there is one.  Also check that this event
     * was not popped off the stack by a memory context being free'd
     * elsewhere.
     */
    if (stackItem && !IsAbortedTransactionBlockState())
    {
        /*
         * Make sure the item we want to log is still on the stack - if not
         * then something has gone wrong and an error will be raised.
         */
        stack_valid(stackId);

        /*
         * Log the utility command if logging is on, the command has not
         * already been logged by another hook, and the transaction is not
         * aborted.
         */
        if (!stackItem->auditEvent.logged)
            log_audit_event(stackItem);
    }
}

/*
 * Hook object_access_hook to provide fully-qualified object names for function
 * calls.
 */
static void
pgaudit_object_access_hook(ObjectAccessType access,
                            Oid classId,
                            Oid objectId,
                            int subId,
                            void *arg)
{
    if (access == OAT_FUNCTION_EXECUTE &&
        auditEventStack && !IsAbortedTransactionBlockState())
        log_function_execute(objectId);

    if (next_object_access_hook)
        (*next_object_access_hook) (access, classId, objectId, subId, arg);
}

/*
 * Event trigger functions
 */

/*
 * Supply additional data for (non drop) statements that have event trigger
 * support and can be deparsed.
 *
 * Drop statements are handled below through the older sql_drop event trigger.
 */
Datum
pgaudit_ddl_command_end(PG_FUNCTION_ARGS)
{
    EventTriggerData *eventData;
    int result,
        row;
    TupleDesc spiTupDesc;
    const char *query;
    MemoryContext contextQuery;
    MemoryContext contextOld;

    /* Be sure the module was loaded */
    if (!auditEventStack)
        elog(ERROR, "pgaudit not loaded before call to "
             "pgaudit_ddl_command_end()");

    /* This is an internal statement - do not log it */
    internalStatement = true;

    /* Make sure the fuction was fired as a trigger */
    if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
        elog(ERROR, "not fired by event trigger manager");

    /* Switch memory context for query */
    contextQuery = AllocSetContextCreate(
                            CurrentMemoryContext,
                            "pgaudit_func_ddl_command_end temporary context",
                            ALLOCSET_DEFAULT_MINSIZE,
                            ALLOCSET_DEFAULT_INITSIZE,
                            ALLOCSET_DEFAULT_MAXSIZE);
    contextOld = MemoryContextSwitchTo(contextQuery);

    /* Get information about triggered events */
    eventData = (EventTriggerData *) fcinfo->context;

    auditEventStack->auditEvent.logStmtLevel =
        GetCommandLogLevel(eventData->parsetree);
    auditEventStack->auditEvent.commandTag =
        nodeTag(eventData->parsetree);
    auditEventStack->auditEvent.command =
        CreateCommandTag(eventData->parsetree);

    /* Return objects affected by the (non drop) DDL statement */
    query = "SELECT UPPER(object_type), object_identity, UPPER(command_tag)\n"
            "  FROM pg_catalog.pg_event_trigger_ddl_commands()";

    /* Attempt to connect */
    result = SPI_connect();
    if (result < 0)
        elog(ERROR, "pgaudit_ddl_command_end: SPI_connect returned %d",
             result);

    /* Execute the query */
    result = SPI_execute(query, true, 0);
    if (result != SPI_OK_SELECT)
        elog(ERROR, "pgaudit_ddl_command_end: SPI_execute returned %d",
             result);

    /* Iterate returned rows */
    spiTupDesc = SPI_tuptable->tupdesc;
    for (row = 0; row < SPI_processed; row++)
    {
        HeapTuple    spiTuple;

        spiTuple = SPI_tuptable->vals[row];

        /* Supply object name and type for audit event */
        auditEventStack->auditEvent.objectType =
            SPI_getvalue(spiTuple, spiTupDesc, 1);
        auditEventStack->auditEvent.objectName =
            SPI_getvalue(spiTuple, spiTupDesc, 2);
        auditEventStack->auditEvent.command =
            SPI_getvalue(spiTuple, spiTupDesc, 3);

        auditEventStack->auditEvent.logged = false;

        /*
         * Identify grant/revoke commands - these are the only non-DDL class
         * commands that should be coming through the event triggers.
         */
        if (pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_GRANT) == 0 ||
            pg_strcasecmp(auditEventStack->auditEvent.command, COMMAND_REVOKE) == 0)
        {
            NodeTag currentCommandTag = auditEventStack->auditEvent.commandTag;

            auditEventStack->auditEvent.commandTag = T_GrantStmt;
            log_audit_event(auditEventStack);

            auditEventStack->auditEvent.commandTag = currentCommandTag;
        }
        else
            log_audit_event(auditEventStack);
    }

    /* Complete the query */
    SPI_finish();

    MemoryContextSwitchTo(contextOld);
    MemoryContextDelete(contextQuery);

    /* No longer in an internal statement */
    internalStatement = false;

    PG_RETURN_NULL();
}

/*
 * Supply additional data for drop statements that have event trigger support.
 */
Datum
pgaudit_sql_drop(PG_FUNCTION_ARGS)
{
    int result,
        row;
    TupleDesc spiTupDesc;
    const char *query;
    MemoryContext contextQuery;
    MemoryContext contextOld;

    /* Be sure the module was loaded */
    if (!auditEventStack)
        elog(ERROR, "pgaudit not loaded before call to "
             "pgaudit_sql_drop()");

    /* This is an internal statement - do not log it */
    internalStatement = true;

    /* Make sure the fuction was fired as a trigger */
    if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
        elog(ERROR, "not fired by event trigger manager");

    /* Switch memory context for the query */
    contextQuery = AllocSetContextCreate(
                            CurrentMemoryContext,
                            "pgaudit_func_ddl_command_end temporary context",
                            ALLOCSET_DEFAULT_MINSIZE,
                            ALLOCSET_DEFAULT_INITSIZE,
                            ALLOCSET_DEFAULT_MAXSIZE);
    contextOld = MemoryContextSwitchTo(contextQuery);

    /* Return objects affected by the drop statement */
    query = "SELECT UPPER(object_type),\n"
        "       object_identity\n"
        "  FROM pg_catalog.pg_event_trigger_dropped_objects()\n"
        " WHERE lower(object_type) <> 'type'\n"
        "   AND schema_name <> 'pg_toast'";

    /* Attempt to connect */
    result = SPI_connect();
    if (result < 0)
        elog(ERROR, "pgaudit_ddl_drop: SPI_connect returned %d",
             result);

    /* Execute the query */
    result = SPI_execute(query, true, 0);
    if (result != SPI_OK_SELECT)
        elog(ERROR, "pgaudit_ddl_drop: SPI_execute returned %d",
             result);

    /* Iterate returned rows */
    spiTupDesc = SPI_tuptable->tupdesc;
    for (row = 0; row < SPI_processed; row++)
    {
        HeapTuple    spiTuple;

        spiTuple = SPI_tuptable->vals[row];

        auditEventStack->auditEvent.objectType =
            SPI_getvalue(spiTuple, spiTupDesc, 1);
        auditEventStack->auditEvent.objectName =
            SPI_getvalue(spiTuple, spiTupDesc, 2);

        auditEventStack->auditEvent.logged = false;
        log_audit_event(auditEventStack);
    }

    /* Complete the query */
    SPI_finish();

    MemoryContextSwitchTo(contextOld);
    MemoryContextDelete(contextQuery);

    /* No longer in an internal statement */
    internalStatement = false;

    PG_RETURN_NULL();
}

/*
 * Define GUC variables and install hooks upon module load.
 */
void
_PG_init(void)
{
    /* Be sure we do initialization only once */
    static bool inited = false;
	MemoryContext old_ctx;

    if (inited)
        return;

    /* Must be loaded with shared_preload_libaries */
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pgaudit must be loaded via shared_preload_libraries")));

    /* Define pgaudit.log_relation */
    DefineCustomBoolVariable(
        "pgaudit.log_relation",

        "Specifies whether session audit logging should create a separate log "
        "entry for each relation referenced in a SELECT or DML statement. "
        "This is a useful shortcut for exhaustive logging without using object "
        "audit logging.",

        NULL,
        &auditLogRelation,
        false,
        PGC_SUSET,
        GUC_NOT_IN_SAMPLE,
        NULL, NULL, NULL);

		/* Define pgaudit.confg_file */
	DefineCustomStringVariable(
		"pgaudit.config_file",
		"Specifies the file path name for pgaudit configuration.",
		NULL,
		&config_file,
		"",
		PGC_POSTMASTER,
		GUC_NOT_IN_SAMPLE,
		NULL, NULL, NULL);

	/*
	 * Install our hook functions after saving the existing pointers to
     * preserve the chains.
     */
    next_ExecutorStart_hook = ExecutorStart_hook;
    ExecutorStart_hook = pgaudit_ExecutorStart_hook;

    next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
    ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

    next_ProcessUtility_hook = ProcessUtility_hook;
    ProcessUtility_hook = pgaudit_ProcessUtility_hook;

    next_object_access_hook = object_access_hook;
    object_access_hook = pgaudit_object_access_hook;

	next_emit_log_hook = emit_log_hook;
	emit_log_hook = pgaudit_emit_log_hook;

	/* Parse audit configuration */
	if (config_file == NULL)
		ereport(ERROR, (errmsg("\"pgaudit.config_file\" must be specify when pgaudit is loaded")));

	old_ctx = MemoryContextSwitchTo(TopMemoryContext);
	outputConfig = (AuditOutputConfig *) malloc(sizeof(AuditOutputConfig));
	ruleConfigs = NULL;

	/* Parse configuration file specified by pgaudit.config_file */
	processAuditConfigFile(config_file);
	print_config(); /* debug output */

	MemoryContextSwitchTo(old_ctx);

    /* Log that the extension has completed initialization */
    ereport(LOG, (errmsg("pgaudit extension initialized")));

    inited = true;
}
