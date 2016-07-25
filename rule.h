/*
 * rule.h
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * IDENTIFICATION
 *           pgaudit/rule.h
 */

#include "postgres.h"
#include "pgaudit.h"

/*
 * String constants used for redacting text after the password token in
 * CREATE/ALTER ROLE commands.
 */
#define TOKEN_PASSWORD             "password"
#define TOKEN_REDACTED             "<REDACTED>"

/*
 * String constants for testing role commands.  Rename and drop role statements
 * are assigned the nodeTag T_RenameStmt and T_DropStmt respectively.  This is
 * not very useful for classification, so we resort to comparing strings
 * against the result of CreateCommandTag(parsetree).
 */
#define COMMAND_ALTER_ROLE          "ALTER ROLE"
#define COMMAND_DROP_ROLE           "DROP ROLE"
#define COMMAND_GRANT               "GRANT"
#define COMMAND_REVOKE              "REVOKE"


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
};

/* Configuration variable types */
enum
{
	AUDIT_RULE_TYPE_INT = 1,
	AUDIT_RULE_TYPE_STRING,
	AUDIT_RULE_TYPE_TIMESTAMP,
	AUDIT_RULE_TYPE_BITMAP
};

/* Macros for rule */
#define isIntRule(rule) \
	((((AuditRule)(rule)).type == AUDIT_RULE_TYPE_INT))
#define isStringRule(rule) \
	((((AuditRule)(rule)).type == AUDIT_RULE_TYPE_STRING))
#define isTimestampRule(rule) \
	((((AuditRule)(rule)).type == AUDIT_RULE_TYPE_TIMESTAMP))
#define isBitmapRule(rule) \
	((((AuditRule)(rule)).type == AUDIT_RULE_TYPE_BITMAP))

/* Fucntion proto types */
extern bool apply_all_rules(AuditEventStackItem *stackItem, bool *valid_rules);
