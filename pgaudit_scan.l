/*
 * pgaudit_scan.l
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 */

/*
 * Token scanner called from pgaudit_parse.y parser
 *
 * IDENTIFICATION
 *           contrib/pgaudit/pgaudit_scan.l
 */

%{
#include "postgres.h"

#include <stdio.h>
#include <stdlib.h>

#include "pgaudit.h"

%}

%option 8bit
%option never-interactive
%option noinput
%option nounput
%option noyywrap
%option warn
%option prefix="pgaudit_yy"

%x COMMENT
%x LITERAL_STATUS

space		[ \t\n\r\f\v]

char		[a-zA-Z\%\,]
string		\'([^'\\\n]|\\.|\'\')*\'
int		[1-9][0-9]*
boolean		off|on|true|false|0|1
op_eq		\=
op_ne		\!=
operator	{op_eq}|{op_ne}

field_output    logger|pathlog|ident|option|facility|priority|level|maxlength
field_options   log_catalog|log_level|log_parameter|log_statement_once|role
field_rule      format|timestamp|database|current_user|user|class|command_tag|object_type|object_id|application_name|command_result|remote_host|shutdown_status|remote_port
%%

<<EOF>>         return AUDIT_EOF;

{space}	{ /* ignore */ }

'\n'	return AUDIT_EOL;

{int}	{
//fprintf(stderr, "INT : %s\n", yytext);
return AUDIT_INT;
}	
{boolean} {
return AUDIT_BOOLEAN;
}
{operator} {
//fprintf(stderr, "operator : %s\n", yytext);
return AUDIT_OP;
}

{field_output} {
//fprintf(stderr, "field_output : %s\n", yytext);

return AUDIT_FIELD_OUTPUT;
}

{field_options} {
//fprintf(stderr, "fieldoptions : %s\n", yytext);
return AUDIT_FIELD_OPTIONS;
}

{field_rule} {
//fprintf(stderr, "field_rule : %s\n", yytext);
return AUDIT_FIELD_RULE;
}

"[output]" {
//fprintf(stderr, "output : %s\n", yytext);
return AUDIT_SECTION_OUTPUT;
}

"[options]" {
//fprintf(stderr, "options : %s\n", yytext);
return AUDIT_SECTION_OPTIONS;
}

"[rule]" {
//fprintf(stderr, "rule : %s\n", yytext);
return AUDIT_SECTION_RULE;
}

{string} {
//fprintf(stderr, "name : %s\n", yytext);
return AUDIT_NAME;
}

%%

/*
 * This function open, read, and process configuration file spcified by
 * filename.
 */
void processAuditConfigFile(char* filename)
{
	FILE *fp;
	int parse_rc = 0;
	AuditRuleConfig *rconf;

	volatile YY_BUFFER_STATE lex_buffer = NULL;
        int  token;

	if ((fp = fopen(filename, "r")) == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_SUCCESSFUL_COMPLETION), /* XXX : error code */
				 errmsg("could not open file \"%s\")", filename)));
	}

	lex_buffer = pgaudit_yy_create_buffer(fp, YY_BUF_SIZE);
	pgaudit_yy_switch_to_buffer(lex_buffer);

	while ((token = yylex()))
	{
		char *field_name = NULL;
		char *value_name = NULL;
		char *op_name = NULL;

		if (token == AUDIT_EOF)
			break;
		if (token == AUDIT_EOL)
			continue;

		if (token == AUDIT_SECTION_RULE ||
  		    token == AUDIT_SECTION_OUTPUT ||
	  	    token == AUDIT_SECTION_OPTIONS)
		{
			/* Set current state */
			audit_parse_state = token;

			if (audit_parse_state == AUDIT_SECTION_RULE)
			{
				rconf = (AuditRuleConfig *) malloc(sizeof(AuditRuleConfig));
				set_default_rule(rconf);
				if (ruleConfig == NULL)
					ruleConfig = list_make1(rconf);
				else
					ruleConfig = lappend(ruleConfig, rconf);
			}
			continue;
		}

		if (token == AUDIT_FIELD_OUTPUT ||
		    token == AUDIT_FIELD_OPTIONS ||
		    token == AUDIT_FIELD_RULE)
		{
			/* Check if invalid field is specified in this section */
			if (!((audit_parse_state == AUDIT_SECTION_RULE && token == AUDIT_FIELD_RULE) ||
			    (audit_parse_state == AUDIT_SECTION_OPTIONS && token == AUDIT_FIELD_OPTIONS) ||
			    (audit_parse_state == AUDIT_SECTION_OUTPUT && token == AUDIT_FIELD_OUTPUT)))
			{
				fprintf(stderr, "section and field are mismatched.\n");
				break;
			}

			/* Get field */
			field_name = pstrdup(yytext);

			/* Get operator */
			token = yylex();
			if (token != AUDIT_OP)
			{
				fprintf(stderr, "Syntax error\n");
				break;
			}
			op_name = pstrdup(yytext);

			/* Get value */	
			token = yylex();
			if (token == AUDIT_NAME ||
				  token == AUDIT_INT ||
				  token == AUDIT_BOOLEAN)
			{
				value_name = pstrdup(yytext);
				validate_settings(field_name, op_name, value_name,
							rconf);
			}
			else
			{
//				fprintf(stderr, "INVALID VALUE %s\n", yytext);
				break;
			}
		}
		else
		{
			fprintf(stderr, "INVALID TOKEN %s\n", yytext);
			break;
		}
	}
	if (parse_rc != 0)
	{
		/* parse error */
		ereport(WARNING,
				(errcode(ERRCODE_SUCCESSFUL_COMPLETION),
				 errmsg( "pgaudit.config_file = %s    => parse error,"
						 "All setting is reset in the default value.", filename)));
	}

	if ((fclose(fp) != 0))
	{
		ereport(ERROR,
				(errcode(ERRCODE_SUCCESSFUL_COMPLETION),
				 errmsg("could not close file \"%s\"", filename)));
	}
}
