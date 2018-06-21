// SPDX-License-Identifier:     GPL-2.0
/* Copyright (c) 2018, Linaro Limited */

#include <command.h>
#include <malloc.h>

#include <xtest_test.h>
#include <xtest_helpers.h>

char *_device = NULL;

static void add_cases(struct adbg_case_def_head *cases)
{
	struct adbg_case_def *begin = ll_entry_start(struct adbg_case_def,
						     regression);
	const size_t len = ll_entry_count(struct adbg_case_def, regression);
	size_t n;

	for (n = 0; n < len; n++)
		TAILQ_INSERT_TAIL(cases, begin + n, link);
}

static int do_xtest(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	int rc;
	TEEC_Result res;
	ADBG_SUITE_DEFINE(regression);

	if (flag == CMD_FLAG_REPEAT)
		return CMD_RET_FAILURE;


	res = xtest_teec_ctx_init();
	if (res) {
		fprintf(stderr, "Failed to open TEE context: 0x%" PRIx32 "\n",
			res);
		rc = CMD_RET_FAILURE;
		goto out;
	}

	add_cases(&ADBG_Suite_regression.cases);

	rc = Do_ADBG_RunSuite(&ADBG_Suite_regression,
			      argc - 1, (void *)(argv + 1));
	if (rc) {
		rc = CMD_RET_FAILURE;
		goto out;
	}

	rc = CMD_RET_SUCCESS;
out:
	xtest_teec_ctx_deinit();
	printf("TEE test application done!\n");
	return rc;
}

U_BOOT_CMD(xtest, CONFIG_SYS_MAXARGS, 0, do_xtest,
	   "Runs the OP-TEE xtest regresession suite\n", NULL);
