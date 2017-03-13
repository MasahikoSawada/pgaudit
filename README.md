[![Build Status](https://travis-ci.org/ossc-db/pgaudit.svg?branch=refactored)](https://travis-ci.org/ossc-db/pgaudit)

# pgaudit/pgaudit
## PostgreSQL Audit Extension
The PostgreSQL Audit extension (`pgaudit`) provides detailed session and/or object audit logging.

The goal of the PostgreSQL Audit extension (`pgaudit`) is to provide PostgreSQL users with capability to produce audit logs often required to comply with government, financial, or ISO certifications.

An audit is an official inspection of an individual's or organization's accounts, typically by an independent body. The information gathered by the PostgreSQL Audit extension (`pgaudit`) is properly called an audit trail or audit log. The term audit log is used in this documentation.

This is a forked `pgaudit` project based on original `pgaudit` project with changing design and adding some fatures.

## Why PostgreSQL Audit Extension?

Basic statement logging can be provided by the standard logging facility. This is acceptable for monitoring and other usages but does not provide the level of detail generally required for an audit. It is not enough to have a list of all the operations performed against the database. It must also be possible to fi\
nd particular statements that are of interest to an auditor. The standard logging facility shows what the user requested, while `pgaudit` focuses on the details of what happened while the database was satisfying the request.

For example, an auditor may want to verify that a particular table was created inside a documented maintenance window. This might seem like a simple job for grep, but what if you are presented with something like this (intentionally obfuscated) example:

```
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
    END $$;
    ```

Standard logging will give you this:

```
LOG:  statement: DO $$
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
    END $$;
    ```

It appears that finding the table of interest may require some knowledge of the code in cases where tables are created dynamically. This is not ideal since it would be preferable to just search on the table name. This is where `pgaudit` comes in. For the same input, it will produce this output in the log:

```
AUDIT: SESSION,33,1,FUNCTION,DO,,,"DO $$
BEGIN
    EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
END $$;"
AUDIT: SESSION,33,2,DDL,CREATE TABLE,TABLE,public.important_table,CREATE TABLE important_table (id INT)
```

Not only is the DO block logged, but substatement 2 contains the full text of the CREATE TABLE with the statement type, object type, and full-qualified name to make searches easy.
When logging SELECT and DML statements, `pgaudit` can be configured to log a separate entry for each relation referenced in a statement. For input "select * from team,member;" it will produce this output in the logs:

```
LOG:  AUDIT: OBJECT,34,1,READ,SELECT,TABLE,public.team,"select * from team,member;",<not logged>
LOG:  AUDIT: OBJECT,34,1,READ,SELECT,TABLE,public.member,"select * from team,member;",<not logged>
```

No parsing is required to find all statements that touch a particular table. In fact, the goal is that the statement text is provided primarily for deep forensics and should not be required for an audit.

## Usage Considerations
Depending on settings, it is possible for `pgaudit` to generate an enormous volume of logging. Be careful to determine exactly what needs to be audit logged in your environment to avoid logging too much.

For example, when working in an OLAP environment it would probably not be wise to audit log inserts into a large fact table. The size of the log file will likely be many times the actual data size of the inserts because the log file is expressed as text. Since logs are generally stored with the OS this may lead to\
 disk space being exhausted very quickly. In cases where it is not possible to limit audit logging to certain tables, be sure to assess the performance impact while testing and allocate plenty of space on the log volume. This may also be true for OLTP environments. Even if the insert volume is not as high, the per\
 formance impact of audit logging may still noticeably affect latency.

To limit the number of relations audit logged for SELECT and DML statements, consider using `Object audit logging` (see Object Audit Logging) and/or `Session audit logging` (see Session Audit Logging).
`Object audit logging` allows selection of the relations to be logged allowing for reduction of the overall log volume. However, when new relations are added they must be explicitly added to `Object audit logging`. A programmatic solution where specified tables are excluded from logging and all others are included\
 may be a good option in this case.
 `Session audit logging` allows selection of logs by rule with filters (see settings), to be logged allowing for reduction of the overall log volume.

## Configuration
pgaudit requires to be set in `shared_preload_libraries`, and it has one GUC parameter `pgaudit.config_file` which specifies the path of configuration file. A setting example is,

```:bash
$ vi $PGDATA/postgresql.conf
shared_preload_libraries = 'pgaudit'
pgaudit.config_file = '/path/to/pgaudit.conf'
```

### pgaudit configuration file
All pgaudit setting is configured in a pgaudit dedicated configuration file specified by `pgaudit.config_file`. The pgaudit configuration file consistes of three sections: **output**, **option** and **rule**. The output section and option section cannot be defined more than once in the configuration file while rule section can be defined more than once. All section names are case-insensitive. The line followed by hash marks(#) designate as a comment.

#### output section
|Parameter|Description|Remarks|
|--------|----------------|------|
|logger|Logger you use; `serverlog` or `syslog`|The default is `serverlog`|
|pathlog|Specifies the socket to which sysloged listens|Parameter for syslog. The default is `/dev/log`|
|facility|See `man 3 syslog` for value|Parameter for syslog|
|priority|See `man 3 syslog` for value|Parameter for syslog|
|ident|See `man 3 syslog` for value|Parameter for syslog|
|option|See `man 3 syslog` for value|Parameter for syslog|

#### option section
|Parameter|Description|Remarks|
|--------|----------------|------|
|role|The role name used by object audit logging|Parameter for **only** object audit logging|
|log_catalog|Logging in case where all relation in a statement are in pg_catalog|The default is `on`|
|log_parameter|Logging statement parameter|The default is `off`|
|log_statement_once|Logging statement text and parameters with the first log entry|The default is `off`|
|log_level|Log level of audit log|The default is `LOG`|

#### rule section
The rule section is used for only session audit logging. Please refer to [Session Audit Logging](/docs/SESSION_LOG.md) for more details.

## Session Audit Logging
Session audit logging provides detailed logs of all statements executed by the user in the backend process, logs for postmaster (a start of database and connection receiving), and logs the error. Unlike object audit logging, session audit logging has a flexible filter of audit log. This feature enables us to narrow down the audit log and keeps to a minimum performance influence. Please see [Session Audit Logging](/docs/SESSION_LOG.md) for more details.

## Object Audit Logging

Object audit logging logs statements that affect a particular relation. Only SELECT, INSERT, UPDATE and DELETE commands are supported. TRUNCATE is not included in `Object audit logging`. Please see [Object Audit Logging](/docs/OBJECT_LOG.md) for more details.

## Installation
### 1. Install PostgreSQL
From the [official site of PostgreSQL](https://www.postgresql.org/) download the source archive file "postgresql-X.Y.Z.tar.gz (please replace X.Y.Z with actual version number)" of PostgreSQL, and then build and install it.

```
$ tar zxf postgresql-X.Y.Z.tar.gz
$ cd postgresql-X.Y.Z
$ ./configure --prefix=/opt/pgsql-X.Y.Z
$ make
$ su
# make install
# exit
```
* --prefix : Specify the PostgreSQL installation directory. This is optional. By default, PostgreSQL is installed in /usr/local/pgsql.

If PostgreSQL installed from RPM, the `postgresql-devel` package must be installed to build pgaudit.
### 2. Install pgaudit
Down load the source archive file of pgaudit or clone repository from github, and then build and install it.
```
$ git clone https://github.com/postgres/postgres.git
$ cd pgaudit
$ make USE_PGXS=1
$ su
# make USE_PGXS=1 install
# exit
```
* USE_PGXS : USE_PGXS=1 must be always specified when building pgaudit.
* If the PATH environment variable doesn't contains the path to pg_config, please set PG_CONFIG.

### 3. Load pgaudit
The installation operation of pgaudit consists of several phase. Please install and load pgaudit by following steps.

#### 3-1. Create the empty rule pgaudit configuration file
Before loading pgaudit create the empty rule pgaudit configuration file.
```
$ vi /path/to/pgaudit.conf
[output]
logger = 'serverlog'
[option]
level = 'LOG'
# Don't define any rule section!
```

#### 3-2. postgresql.conf setting

```
$ vi $PGDATA/postgresql.conf
shared_preload_libraries = 'pgaudit'
pgaudit.config_file = '/path/to/pgaudit.conf'
```

#### 3-3. Start PostgreSQL server
Please make sure the log message `LOG:  pgaudit extension initialized` is appeared in the server log.

#### 3-4. Create pgaudit extension on PostgreSQL server
```
$ psql
=# CREATE EXTENSION pgaudit;
=# \dx
 List of installed extensions
 Name    | Version |	Schema  |	     Description
---------+---------+------------+---------------------------------
 pgaudit | 1.0     | public     | provides auditing functionality
 plpgsql | 1.0     | pg_catalog | PL/pgSQL procedural language
(2 rows)
```

#### 3-5. Rewrite pgaudit configuration file
After created pgaudit extension on PostgreSQL, please rewrite the pgaudit configuration file as you want.

#### 3-6. Restart PostgreSQL server
To apply changes, please restart PostgreSQL server. When restarting please make sure that your configuration is applied properly.

```
LOG:  log_level_string = LOG
LOG:  log_level = 15
LOG:  log_parameter = 0
LOG:  log_statement_once = 0
LOG:  log_for_test = 0
LOG:  role =
LOG:  logger = serverlog
LOG:  facility = (null)
LOG:  priority = (null)
LOG:  ident = (null)
LOG:  option = (null)
LOG:  pathlog = (null)
LOG:  Rule 0
LOG:      STR database = hoge_db
LOG:      BMP class = 320
LOG:      STR object_name = hoge_schema.hoge_table
LOG:  Rule 1
LOG:      STR database = hoge_db
LOG:      BMP class = 4
```

## Uninstallation
### 1. Delete pgaudit
Unload pgaudit from the database and then uinstall it.
```
$ psql -d <database name>
=# DROP EXTENSION pgaudit;
=# \q
$ pg_ctl stop
$ su
# cd <pgaudit source directory>
# make USE_PGXS=1 uninstall
# exit
```
### 2. Reset postgresql.conf
Delete the following pgaudit related settings from postgresql.conf.

* `shared_preload_libraries`
* `pgaudit.config_file` paramter

## Note

- Using syslogd

 To use the syslogd (in case of rsyslog) for `pgaudit`, consider the parameter following:

 - $MaxMessageSize

     This should be set to a value greater than the length of the longest audit log message. Otherwise, the rear of the log message may be lost.

 - $SystemLogSocketName

     Value to be set in the pathlog of `output-section`.

 - $EscapeControlCharactersOnReceive

 This should be set to off. Otherwise, control characters in the log message will be converted to escapes. (E.g. #011('\t'), #012('\n'))

- Logs of error

 `Session audit logging` logs a log for a SQL (Success or Error) for simple SQL, but sometimes, especially for complex SQL, logs some of logs (for each parts and an Error).

- pgaudit must be set log\_connections, log\_disconnections and log\_replication\_commands is on. If all these parameters are not on, the PostgreSQL server will not start.
  - To ensure that these parameter cannot be changed after started, pgaudit forcibly changes the context of these three parameters to `postmaster`.

## Authors

The PostgreSQL Audit Extension is based on the pgaudit project at https://github.com/pgaudit/pgaudit.
