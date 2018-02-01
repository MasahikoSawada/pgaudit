/*
 * pgaudit_scan.l
 *
 * Copyright (c) 2016, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * IDENTIFICATION
 *           pgaudit/pgaudit_scan.l
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

space		[ \t\n\r\f\v]

val_string	\'([^'\\\n]|\\.|\'\')*\'
int		[1-9][0-9]*
boolean		off|on|true|false|0|1
op_eq		\=
op_ne		\!=
operator	{op_eq}|{op_ne}
comment		#.*

field_output    logger|pathlog|ident|option|facility|priority|level|maxlength
field_option    log_catalog|log_level|log_parameter|log_statement_once|role|log_for_test
field_rule      format|timestamp|database|audit_role|class|command_tag|object_type|object_name|application_name|command_result|remote_host|remote_port
%%

<<EOF>>         return AUDIT_EOF;

{space}	{ /* ignore */ }
'\n'	return AUDIT_EOL;
{comment}	return AUDIT_EOL;
{int}		return AUDIT_INT;
{boolean}	return AUDIT_BOOLEAN;
{operator}	return AUDIT_OP;
{field_output}	return AUDIT_FIELD_OUTPUT;
{field_option}	return AUDIT_FIELD_OPTION;
{field_rule}	return AUDIT_FIELD_RULE;
"[output]"	return AUDIT_SECTION_OUTPUT;
"[option]"	return AUDIT_SECTION_OPTION;
"[rule]"	return AUDIT_SECTION_RULE;
{val_string}	return AUDIT_NAME;
.		{
			ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
					errmsg("error invalid token \"%s\" in \"%s\"",
					yytext, get_auditsection_string(audit_parse_state))));
		}
%%

/*
 * This function open, read, and process configuration file spcified by
 * filename.
 */
void processAuditConfigFile(char* filename)
{
	FILE *fp;
	AuditRuleConfig *rconf = NULL;
	bool output_section_given = false;
	bool option_section_given = false;

	volatile YY_BUFFER_STATE lex_buffer = NULL;
        int  token;

	if ((fp = fopen(filename, "r")) == NULL)
	{
		ereport(ERROR,
			       (errcode_for_file_access(),
				 errmsg("could not open file \"%s\"", filename)));
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

		/* Detected secion string */
		if (token == AUDIT_SECTION_RULE ||
			token == AUDIT_SECTION_OUTPUT ||
			token == AUDIT_SECTION_OPTION)
		{
			/* Set current state */
			audit_parse_state = token;

			switch(audit_parse_state)
			{
				case AUDIT_SECTION_OUTPUT:
				{
					if (output_section_given)
						ereport(ERROR,
							(errcode(ERRCODE_CONFIG_FILE_ERROR),
							errmsg("redundant output section defined in file \"%s\"",
								filename)));

					output_section_given = true;
					break;
				}
				case AUDIT_SECTION_OPTION:
				{
					if (option_section_given)
						ereport(ERROR,
							(errcode(ERRCODE_CONFIG_FILE_ERROR),
							errmsg("redundant option section defined in file \"%s\"",
								filename)));

					option_section_given = true;
					break;
				}
				case AUDIT_SECTION_RULE:
				{
					/* Allocate new ruleconfig and set template variables */
					rconf = (AuditRuleConfig *) palloc(sizeof(AuditRuleConfig));
					memcpy(rconf->rules, rules_template, sizeof(AuditRule) * AUDIT_NUM_RULES);

					if (ruleConfigs == NULL)
						ruleConfigs = list_make1(rconf);
					else
						ruleConfigs = lappend(ruleConfigs, rconf);
					break;
				}
			}
			continue;
		}

		/* Detected field string */
		if (token == AUDIT_FIELD_OUTPUT ||
		    token == AUDIT_FIELD_OPTION ||
		    token == AUDIT_FIELD_RULE)
		{
			/* Check if invalid field is specified in this section */
			if (!((audit_parse_state == AUDIT_SECTION_RULE && token == AUDIT_FIELD_RULE) ||
			    (audit_parse_state == AUDIT_SECTION_OPTION && token == AUDIT_FIELD_OPTION) ||
			    (audit_parse_state == AUDIT_SECTION_OUTPUT && token == AUDIT_FIELD_OUTPUT)))
				ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
						errmsg("invalid parameter \"%s\" in \"%s\" in file \"%s\"",
						       yytext, get_auditsection_string(audit_parse_state),
							filename)));

			/* Get field */
			field_name = pstrdup(yytext);

			/* Get operator */
			token = yylex();
			if (token != AUDIT_OP)
			{
				ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
						errmsg("invalid operator \"%s\" in file \"%s\"", yytext, filename)));
			}

			op_name = pstrdup(yytext);

			/* Get value */
			token = yylex();

			if (token == AUDIT_NAME ||
				  token == AUDIT_INT)
			{
				value_name = audit_scanstr(yytext);
				validate_settings(field_name, op_name, value_name, rconf);
			}
			else if (token == AUDIT_BOOLEAN)
			{
				value_name = pstrdup(yytext);
				validate_settings(field_name, op_name, value_name, rconf);
			}
			else
				ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
						errmsg("syntax error near token \"%s\" in file \"%s\"",
						       yytext, filename)));
		}
		else
			ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
					errmsg("unrecognized configuration token \"%s\" in \"%s\" in file \"%s\"",
					       yytext, get_auditsection_string(audit_parse_state), filename)));
	}

	if ((fclose(fp) != 0))
	{
		ereport(ERROR,
				(errcode(errcode_for_file_access()),
				 errmsg("could not close file \"%s\"", filename)));
	}
}
