/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Linaro Limited
 *
 */

#include <tee_client_api.h>
#include "xtest_test.h"
#include "xtest_helpers.h"
#include "tpm_cmd.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pta_invoke_tests.h>


static TEEC_Context teec_ctx;
static TEEC_Session teec_sess;

static int usage(void)
{
	errx(1, "usage");
}

int tpm_cmd(int argc, char *argv[])
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_SUCCESS;
	uint32_t ret_orig = 0;
	uint32_t cmdid = 0;
	char *eptr = NULL;

	if (argc != 3)
		return usage();

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
                                         TEEC_NONE, TEEC_NONE);

	if (!strcmp(argv[1], "nv_read"))
		cmdid = PTA_INVOKE_TESTS_CMD_NV_READ;
	else if (!strcmp(argv[1], "nv_write"))
		cmdid = PTA_INVOKE_TESTS_CMD_NV_WRITE;
	else if (!strcmp(argv[1], "nv_define"))
		cmdid = PTA_INVOKE_TESTS_CMD_NV_DEFINE;
	else
		return usage();

	op.params[0].value.a = strtoul(argv[2], &eptr, 0);

	printf("%s %#"PRIx32"\n", argv[1], op.params[0].value.a);

	res = TEEC_InitializeContext(NULL, &teec_ctx);
	if (res)
		errx(1, "TEEC_InitializeContext: %#"PRIx32, res);

	res = TEEC_OpenSession(&teec_ctx, &teec_sess, &pta_invoke_tests_ta_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res)
		errx(1, "TEEC_OpenSession: %#"PRIx32, res);

	res = TEEC_InvokeCommand(&teec_sess, cmdid, &op, &ret_orig);
	if (res)
		errx(1, "TEEC_InvokeCommand: %#"PRIx32, res);

	return 0;
}
