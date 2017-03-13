# Session Audit Logging
Session audit logging provides detailed logs of all statements executed by the user in the backend process, logs for postmaster (a start of database and connection receiving), and logs the error. Unlike object audit logging, session audit logging has a flexible filter of audit log. This feature enables us to narrow down the audit log and keeps to a minimum performance influence.

## Configuration
A filter is defined by a set of expression, which begins with a `field = 'value'` style. The operator `!=` represent "not match". The following table shows all field can be set in rule section.

|Field name|Description|Sample setting|
|----------|-----------|---------------|
|timestamp|Timestamp range|`timestamp = '09:00:00 - 10:00:00, 18:00:00 - 18:30:00`|
|database|Database name|`datebase = 'prodcut_db'`|
|audit_role|Role name| `audit_role = 'appuser1'`|
|class|Type of operation. Possible values are, <br> BACKUP, CONNECT, DDL, ERROR, FUNCTION, MISC, READ, ROLE, WRITE, SYSTEM|`class = 'READ, WRITE'`|
|command_tag||`command_tag = 'CREATE, SELECT'`|
|object_type|Type of object. Possible values are,<br> TABLE, INDEX, SEQUENCE, TOAST_VALUE, VIEW, MATERIALIZED_VIEW, COMPOSITE_TYPE, FOREIGN_TABLE, FUNCTION|`object_type = 'TABLE, INDEX'`|
|object_name|Qualified object name|`object_name = 'myschema.hoge_table'`|
|application_name|Connecting application name|`application_name = 'myapp'`|
|remote_host|Host name|`remote_host = 'ap_server'`|

For more detail of each fields,

* timestamp

Specifies the filter by timestamps. When this keyword is used in an expression, possible values in the left-hand side are an interval and comma delimited intervals, which is a pair of timestamps (start and end). The format for timestamp pair is fixed as 'hh:mm:dd-hh:mm:dd';
 hh,mm and dd, are 2 digits, hh is 24-hour representation. And in an interval, the start timestamp should be smaller (earlier) than the end timestamp.

The end of an interval is prolonged to just before the next second of later timestamp. For example, '11:00:00-11:59:59' means an interval, 'starts at just 11:00:00' and 'ends at just before 12:00:00 (=11:59.59 999msec).
The timestamp used `pgaudit` rule evaluation internally is different from one issued in the log entry. Because when `pgaudit` output a log entry after evaluation, it generates timestamp for log entry.

* class

The details of each values are:
* READ: SELECT and COPY FROM.
* WRITE: INSERT, UPDATE, DELETE, TRUNCATE, and COPY TO.
* FUNCTION: Function calls and DO blocks.
* ROLE: Statements related to roles and privileges: GRANT, REVOKE, CREATE/ALTER/DROP ROLE.
* DDL: All DDL that is not included in the ROLE class.
* CONNECT : Connection events. request, authorized, and disconnect.
* SYSTEM : Server start up. ready, normal and interrupted.
* BACKUP : pg_basebackup.
* ERROR : Event that ended by an error (PostgreSQL Error Code is not in the Class 00 ). Available when log_min_message is set to ERROR or lower.
    *  Logging the messages; connection receiving, authorized, disconnected, database system is ready, normal shutdown, interrupted shutdown.
* MISC: Miscellaneous commands, e.g. DISCARD, FETCH, CHECKPOINT, VACUUM.

## Rule evaluation
When a log event arrives, all expression are evaluated at once. The log entry is output only when **all expression** in a rule section are evaluated true. For example, if we set the following rule, the audit log is output only when the `apserver` does other than write the table `myschema.hoge` during 10 am to 11 am.
```
[rule]
timestamp = '10:00:00-11:00:00'
remote_host = 'apserver'
object_name = 'myschema.hoge_table'
class != 'WRITE'
```

Also, multiple rule can be defined in a pgaudit configuration file. A log event is evaluated by each rules, and the audit log is output whenever each rule is matched. For example, if you configured pgaudit as follows, you will get two duplicate audit log.
```
[rule]
object_name = 'myschema.hoge_table'
[rule]
object_name = 'myschema.hoge_table'
```

## Audit log format
The audit session log is output with fixed format. The following table shows the audit log format.

|Column #|Contents|
|----|--------|
|1|Session audit log header. Fixed string `AUDIT: SESSION`|
|2|Class|
|3|Timestamp|
|4|Remote host|
|5|Backend process ID|
|6|Application name|
|7|Session user name|
|8|Database name|
|9|Virtual transaction ID|
|10|Statement ID|
|11|Substatement ID|
|12|Command tag|
|13|SQLSTATE|
|14|Object type|
|15|Object name|
|16|Error message|
|17|SQL|
|18|Parameter|

## Example

In this example Session audit logging is used for logging DDL and SELECT statements. Note that the insert statement is not logged since the WRITE class is not enabled.

### 1. Setting
Define a rule in pgaudit configuration file like follows.

```
$ vi audit.conf
:
[rule]
class = 'READ, WRITE'
object_name = 'myschema.account'
```

### 2. Logging session audit

If the client executes the following SQL,
```sql
CREATE TABLE account
(
    id int,
    name text,
    password text,
    description text
);
INSERT INTO account (id, name, password, description) VALUES (1, 'user1', 'HASH1', 'blah, blah');
SELECT * FROM account;
```

You will get the following audit logs.

```
LOG:  AUDIT: SESSION,WRITE,2017-03-12 19:00:49 PDT,[local],19944,psql,appuser,postgres,2/7,1,1,INSERT,,TABLE,myschema.account,,"INSERT INTO myschema.account (id, name, password, description) VALUES (1, 'user1', 'HASH1', 'blah, blah');",<not logged>
LOG:  AUDIT: SESSION,READ,2017-03-12 19:00:58 PDT,[local],19944,psql,appuser,postgres,2/8,2,1,SELECT,,TABLE,myschema.account,,SELECT * FROM myschema.account;,<not logged>
```

Please make sure that since class `DDL` is not define in class parameter, `CREATE TABLE` DDL is not appeared in audit log file.
