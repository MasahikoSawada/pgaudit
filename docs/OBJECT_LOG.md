# Object Audit Logging

Object audit logging logs statements that affect a particular relation. Only SELECT, INSERT, UPDATE and DELETE commands are supported. TRUNCATE is not included in `Object audit logging`.

## Configuration
Object audit logging is implemented via the roles system. The option.role setting defines the role that will be used for audit logging. A relation (TABLE, VIEW, etc.) will be audit logged when the audit role has permissions for the command executed or inherits the permissions from another role. This allows you to effectively have multiple audit roles even though there is a single master role in any context.
Set `role` in option section to auditor and grant SELECT and DELETE privileges on the account table. Any SELECT or DELETE statements on account will now be logged:

## Audit log format
The audit log by object audit log is fixed format as follows.

|Column #|Contents|
|----|--------|
|1|Object audit log header. Fixed string `AUDIT: OBJECT`|
|2|Statement id|
|3|Substatement id|
|4|Class|
|5|Command tag|
|6|Object type
|7|Object name|
|8|SQL|

## Example

In this example Object audit logging is used to illustrate how a granular approach may be taken towards logging of SELECT and DML statements. Note that logging on the account table is controlled by column-level permissions, while logging on account_role_map is table-level.

### 1. Setting
Create new user for object auditing and specify it as a audit user by setting `role` parameter in option section.

```
$ vi audit.conf
:
[option]
role = 'auditor'
:
$ psql
=# CREATE USER auditor NOSUPERUSER LOGIN;
=# GRANT SELECT, DELETE ON public.account To auditor;
```
### 2. Logging object audit
If the client executes the following SQL,
```sql
CREATE TABLE account
(
    id int,
    name text,
    password text,
    description text
);
GRANT SELECT (password) ON public.account TO auditor;
SELECT id, name FROM account;
SELECT password FROM account;
GRANT UPDATE (name, password) ON public.account TO auditor;
UPDATE account SET description = 'yada, yada';
UPDATE account SET password = 'HASH2';
CREATE TABLE account_role_map
(
    account_id int,
    role_id int
);
GRANT SELECT ON public.account_role_map TO auditor;
SELECT account.password, account_role_map.role_id
  FROM account
  INNER JOIN account_role_map ON account.id = account_role_map.account_id
```

You will get the following audit logs.

```
AUDIT: OBJECT,1,1,READ,SELECT,TABLE,public.account,SELECT password FROM account
AUDIT: OBJECT,2,1,WRITE,UPDATE,TABLE,public.account,UPDATE account SET password = 'HASH2'
AUDIT: OBJECT,3,1,READ,SELECT,TABLE,public.account,SELECT account.password, account_role_map.role_id
	    FROM account
            INNER JOIN account_role_map ON account.id = account_role_map.account_id
```
