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

/*/*
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
 * For audit logging, we must emit not only SQL but alos other utility log
 * such as connection, disconnection, replication command even if log_min_messages
 * is not enough to emit these logs. To support this, we define message-IDs used
 * by emit_log_hook to pull log messages out to audit logging.  These messages
 * will have to be considered when log message is changed.
*/
#define AUDIT_MSG_CONNECTION_RECV	"connection received: host="
#define AUDIT_MSG_CONNECTION_AUTH	"connection authorized: user="
#define AUDIT_MSG_DISCONNECTION		"disconnection: session time:"
#define AUDIT_MSG_SHUTDOWN			"database system was shut down at"
#define AUDIT_MSG_SHUTDOWN_IN_RECOV	"database system was shut down in recovery at"
#define AUDIT_MSG_INTERRUPT			"database system was interrupted"
#define AUDIT_MSG_CONNECTION_READY	"database system is ready to accept connections"
#define AUDIT_MSG_REPLICATION		"received replication command: BASE_BACKUP"
#define AUDIT_MSG_NEW_TLID			"selected new timeline ID:"

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
extern bool apply_all_rules(AuditEventStackItem *stackItem, ErrorData *edata,
							int class, char *className, bool *valid_rules);
extern char *classify_statement_class(AuditEventStackItem *stackItem,
									  int *class);
extern char *classify_edata_class(ErrorData *edata, int *class);
