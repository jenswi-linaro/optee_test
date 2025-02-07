/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2025, Linaro Limited */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_gstaes.h>

#define TA_UUID TA_GSTAES_UUID

#define TA_FLAGS		(TA_FLAG_SECURE_DATA_PATH | \
				 TA_FLAG_CACHE_MAINTENANCE)
#define TA_STACK_SIZE		(32 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
