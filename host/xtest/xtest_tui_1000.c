/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <ta_tui_test.h>
#include <util.h>

#define TUI_BOLD	"\ue000"
#define TUI_UNDERLINE	"\ue001"
#define	TUI_RIGHT	"\ue002"
#define TUI_DOWN	"\ue003"

static void xtest_tui_1001(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;
	char pin[256];
	char label_text[] = "x" TUI_BOLD "test " TUI_UNDERLINE "read"
				TUI_BOLD " pin";

	res = xtest_teec_open_session(&sess, &tui_ta_uuid, NULL, &orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = label_text;
	op.params[0].tmpref.size = strlen(label_text);
	op.params[1].tmpref.buffer = pin;
	op.params[1].tmpref.size = sizeof(pin);

	res = TEEC_InvokeCommand(&sess, TA_TUI_CMD_READ_PIN, &op, &orig);
	if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
		Do_ADBG_Log("Got pin (len %zu) \"%.*s\"",
			    op.params[1].tmpref.size,
			    (int)op.params[1].tmpref.size,
			    (char *)op.params[1].tmpref.buffer);

	TEEC_CloseSession(&sess);
}

static void xtest_tui_1002(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;
	char username[256];
	char password[256];
	char label_text[] = "Login to some service";

	res = xtest_teec_open_session(&sess, &tui_ta_uuid, NULL, &orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = label_text;
	op.params[0].tmpref.size = strlen(label_text);
	op.params[1].tmpref.buffer = username;
	op.params[1].tmpref.size = sizeof(username);
	op.params[2].tmpref.buffer = password;
	op.params[2].tmpref.size = sizeof(password);

	res = TEEC_InvokeCommand(&sess, TA_TUI_CMD_READ_LOGIN, &op, &orig);
	if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Got username (len %zu) \"%.*s\"",
			    op.params[1].tmpref.size,
			    (int)op.params[1].tmpref.size,
			    (char *)op.params[1].tmpref.buffer);
		Do_ADBG_Log("Got password (len %zu) \"%.*s\"",
			    op.params[2].tmpref.size,
			    (int)op.params[2].tmpref.size,
			    (char *)op.params[2].tmpref.buffer);
	}

	TEEC_CloseSession(&sess);
}

static void xtest_tui_1003(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;
	char label_text[] = "A message\r"
			    TUI_BOLD "you" TUI_BOLD " can only\r"
			    TUI_UNDERLINE "accept";

	res = xtest_teec_open_session(&sess, &tui_ta_uuid, NULL, &orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = label_text;
	op.params[0].tmpref.size = strlen(label_text);

	res = TEEC_InvokeCommand(&sess, TA_TUI_CMD_MESSAGE, &op, &orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&sess);
}

static void xtest_tui_1004(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;
	char label_text[] = "A message\r"
			    TUI_BOLD "you" TUI_BOLD " can\r"
			    TUI_UNDERLINE "accept" TUI_UNDERLINE " or "
			    TUI_UNDERLINE "refuse";

	res = xtest_teec_open_session(&sess, &tui_ta_uuid, NULL, &orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = label_text;
	op.params[0].tmpref.size = strlen(label_text);

	res = TEEC_InvokeCommand(&sess, TA_TUI_CMD_VALIDATE_MESSAGE,
				 &op, &orig);
	Do_ADBG_Log("Message %s",
		    op.params[1].value.a ? "accepted" : "resused");
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&sess);
}

static void xtest_tui_1005(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;

	res = xtest_teec_open_session(&sess, &tui_ta_uuid, NULL, &orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT);
	op.params[0].tmpref.buffer = (char *)"Message 1";
	op.params[0].tmpref.size = strlen(op.params[0].tmpref.buffer);
	op.params[1].tmpref.buffer = (char *)"Message 2";
	op.params[1].tmpref.size = strlen(op.params[1].tmpref.buffer);
	op.params[2].tmpref.buffer = (char *)"Message 3";
	op.params[2].tmpref.size = strlen(op.params[2].tmpref.buffer);

	res = TEEC_InvokeCommand(&sess, TA_TUI_CMD_VALIDATE_MESSAGES,
				 &op, &orig);
	Do_ADBG_Log("Message %s",
		    op.params[3].value.a ? "accepted" : "resused");
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&sess);
}

ADBG_CASE_DEFINE(XTEST_TUI_1001, xtest_tui_1001,
		/* Title */
		"Trusted UI Read PIN",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TUI_1002, xtest_tui_1002,
		/* Title */
		"Trusted UI Read login",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);


ADBG_CASE_DEFINE(XTEST_TUI_1003, xtest_tui_1003,
		/* Title */
		"Trusted UI message",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TUI_1004, xtest_tui_1004,
		/* Title */
		"Trusted UI validate message",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TUI_1005, xtest_tui_1005,
		/* Title */
		"Trusted UI validate messages",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);
