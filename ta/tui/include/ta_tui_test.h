/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TA_TUI_TEST_H
#define __TA_TUI_TEST_H

/*
 * This file provides a interface to the test TUI TA. Note that this isn't
 * an example on how to write a TA using TUI, it's only an application that
 * in a not fully secure way exercises the TEE Internal TUI API.
 */

#define TA_TUI_TEST_UUID { 0x961754ba, 0x9d8d, 0x4ac2, \
	{ 0xa8, 0x19, 0xe3, 0x38, 0x1f, 0xf6, 0xd1, 0xcf } }

/*
 * Prompt the user to enter a PIN
 * [in]  memref[0]: label
 * [out] memref[1]: pin
 */
#define TA_TUI_CMD_READ_PIN		1

/*
 * Prompt the user to enter username and password
 * [in]  memref[0]: label
 * [out] memref[1]: username
 * [out] memref[2]: password
 */
#define TA_TUI_CMD_READ_LOGIN		2

/*
 * Display a message
 * [in]  memref[0]: label
 */
#define TA_TUI_CMD_MESSAGE		3

/*
 * Display a message to validate
 * [in]  memref[0]: label
 * [out] value[1].a: true if validated
 */
#define TA_TUI_CMD_VALIDATE_MESSAGE	4

/*
 * Display a message screens to validate
 * [in]  memref[0]: label1
 * [in]  memref[1]: label2
 * [in]  memref[2]: label3
 * [out] value[3].a: true if validated
 */
#define TA_TUI_CMD_VALIDATE_MESSAGES	5

#endif /*__TA_TUI_TEST_H*/
