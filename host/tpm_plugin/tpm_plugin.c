// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Open Mobile Platform LLC
 */

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_plugin_method.h>
#include <tpm_plugin.h>
#include <unistd.h>

static TEEC_Result tpm_plugin_invoke(unsigned int cmd, unsigned int sub_cmd,
				     void *data, size_t data_len,
				     size_t *out_len)
{
	static const char devname[] = "/dev/tpm0";
	static int fd = -1;
	ssize_t sz = -1;

	if (sub_cmd > data_len) {
		warnx("Too large TPM data %u (max %zu)", sub_cmd, data_len);
		return TEEC_ERROR_GENERIC;
	}

	if (fd == -1) {
		fd = open(devname, O_RDWR);
		if (fd < 0) {
			warn("open(%s)", devname);
			return TEEC_ERROR_GENERIC;
		}
	}

	sz = write(fd, data, sub_cmd);
	if (sz < sub_cmd) {
		if (sz < 0)
			warn("write to TPM failed");
		else
			warnx("Short write to TPM %zd of %zu", sz, data_len);
		return TEEC_ERROR_GENERIC;
	}

	sz = read(fd, data, data_len);
	if (sz <= 0) {
		if (sz == 0)
			warnx("read EOF from TPM");
		else
			warn("read from TPM failed");
		return TEEC_ERROR_GENERIC;
	}
	*out_len = sz;
	return TEEC_SUCCESS;;
}

struct plugin_method plugin_method = {
	.name = "tpm",
	.uuid = TPM_PLUGIN_UUID,
	.invoke = tpm_plugin_invoke,
};
