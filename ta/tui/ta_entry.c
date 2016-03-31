/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_tui_api.h>
#include <user_ta_header_defines.h>
#include <ta_tui_test.h>
#include <trace.h>
#include <string.h>
#include <stdlib.h>
#include <util.h>

static TEE_Result cmd_read_pin(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_TUIScreenInfo scr_info;
	TEE_TUIScreenConfiguration scr_cfg;
	TEE_TUIEntryField ent_fld;
	TEE_TUIButtonType button_type;
	char buf[8];
	char *text = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	text = strndup(params[0].memref.buffer, params[0].memref.size);
	if (!text)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_TUIGetScreenInfo(TEE_TUI_LANDSCAPE, 2, &scr_info);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIGetScreenInfo: fail %#" PRIx32, res);
		goto out;
	}

	res = TEE_TUIInitSession();
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIInitSession: fail %#" PRIx32, res);
		goto out;
	}

	memset(&scr_cfg, 0, sizeof(scr_cfg));
	scr_cfg.screenOrientation = TEE_TUI_LANDSCAPE;
	scr_cfg.label.text = text;
	scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
	scr_cfg.requestedButtons[TEE_TUI_VALIDATE] = true;

	memset(&ent_fld, 0, sizeof(ent_fld));
	ent_fld.label = (char *)"secret pin";
	ent_fld.mode = TEE_TUI_HIDDEN_MODE;
	ent_fld.type = TEE_TUI_NUMERICAL;
	ent_fld.buffer = buf;
	ent_fld.bufferLength = sizeof(buf);
	ent_fld.minExpectedLength = 4;
	ent_fld.maxExpectedLength = ent_fld.bufferLength - 1;

	res = TEE_TUIDisplayScreen(&scr_cfg, true, &ent_fld, 1, &button_type);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIDisplayScreen: fail %#" PRIx32, res);
		goto out;
	}
	EMSG("Button %d pressed", button_type);
	if (button_type == TEE_TUI_VALIDATE) {
		memcpy(params[1].memref.buffer, ent_fld.buffer,
		       ent_fld.bufferLength);
		params[1].memref.size = ent_fld.bufferLength;
	} else {
		params[1].memref.size = 0;
	}
out:
	free(text);
	return res;
}

static TEE_Result cmd_read_login(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_TUIScreenInfo scr_info;
	TEE_TUIScreenConfiguration scr_cfg;
	TEE_TUIEntryField ent_fld[2];
	TEE_TUIButtonType button_type;
	char username[17];
	char password[17];
	char *text = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	text = strndup(params[0].memref.buffer, params[0].memref.size);
	if (!text)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_TUIGetScreenInfo(TEE_TUI_LANDSCAPE, 2, &scr_info);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIGetScreenInfo: fail %#" PRIx32, res);
		goto out;
	}

	res = TEE_TUIInitSession();
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIInitSession: fail %#" PRIx32, res);
		goto out;
	}

	memset(&scr_cfg, 0, sizeof(scr_cfg));
	scr_cfg.screenOrientation = TEE_TUI_LANDSCAPE;
	scr_cfg.label.text = text;
	scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
	scr_cfg.requestedButtons[TEE_TUI_VALIDATE] = true;

	memset(ent_fld, 0, sizeof(ent_fld));
	ent_fld[0].label = (char *)"Username";
	ent_fld[0].mode = TEE_TUI_CLEAR_MODE;
	ent_fld[0].type = TEE_TUI_ALPHANUMERICAL;
	ent_fld[0].buffer = username;
	ent_fld[0].bufferLength = sizeof(username);
	ent_fld[0].minExpectedLength = 0;
	ent_fld[0].maxExpectedLength = ent_fld[0].bufferLength;

	ent_fld[1].label = (char *)"Password";
	ent_fld[1].mode = TEE_TUI_TEMPORARY_CLEAR_MODE;
	ent_fld[1].type = TEE_TUI_ALPHANUMERICAL;
	ent_fld[1].buffer = password;
	ent_fld[1].bufferLength = sizeof(password);
	ent_fld[1].minExpectedLength = 4;
	ent_fld[1].maxExpectedLength = ent_fld[1].bufferLength;

	res = TEE_TUIDisplayScreen(&scr_cfg, true, ent_fld, 2, &button_type);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIDisplayScreen: fail %#" PRIx32, res);
		goto out;
	}
	EMSG("Button %d pressed", button_type);
	if (button_type == TEE_TUI_VALIDATE) {
		memcpy(params[1].memref.buffer, ent_fld[0].buffer,
		       ent_fld[0].bufferLength);
		params[1].memref.size = ent_fld[0].bufferLength;

		memcpy(params[2].memref.buffer, ent_fld[1].buffer,
		       ent_fld[1].bufferLength);
		params[2].memref.size = ent_fld[1].bufferLength;
	} else {
		params[1].memref.size = 0;
		params[2].memref.size = 0;
	}
out:
	free(text);
	return res;
}

static TEE_Result cmd_message(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_TUIScreenInfo scr_info;
	TEE_TUIScreenConfiguration scr_cfg;
	TEE_TUIButtonType button_type;
	char *text = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	text = strndup(params[0].memref.buffer, params[0].memref.size);
	if (!text)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_TUIGetScreenInfo(TEE_TUI_LANDSCAPE, 2, &scr_info);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIGetScreenInfo: fail %#" PRIx32, res);
		goto out;
	}

	res = TEE_TUIInitSession();
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIInitSession: fail %#" PRIx32, res);
		goto out;
	}

	memset(&scr_cfg, 0, sizeof(scr_cfg));
	scr_cfg.screenOrientation = TEE_TUI_LANDSCAPE;
	scr_cfg.label.text = text;
	scr_cfg.requestedButtons[TEE_TUI_OK] = true;

	res = TEE_TUIDisplayScreen(&scr_cfg, true, NULL, 0, &button_type);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIDisplayScreen: fail %#" PRIx32, res);
		goto out;
	}
	EMSG("Button %d pressed", button_type);
out:
	free(text);
	return res;
}

static TEE_Result cmd_validate_message(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_TUIScreenInfo scr_info;
	TEE_TUIScreenConfiguration scr_cfg;
	TEE_TUIButtonType button_type;
	char *text = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	text = strndup(params[0].memref.buffer, params[0].memref.size);
	if (!text)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_TUIGetScreenInfo(TEE_TUI_LANDSCAPE, 2, &scr_info);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIGetScreenInfo: fail %#" PRIx32, res);
		goto out;
	}

	res = TEE_TUIInitSession();
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIInitSession: fail %#" PRIx32, res);
		goto out;
	}

	memset(&scr_cfg, 0, sizeof(scr_cfg));
	scr_cfg.screenOrientation = TEE_TUI_LANDSCAPE;
	scr_cfg.label.text = text;
	scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
	scr_cfg.requestedButtons[TEE_TUI_VALIDATE] = true;

	res = TEE_TUIDisplayScreen(&scr_cfg, true, NULL, 0, &button_type);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIDisplayScreen: fail %#" PRIx32, res);
		goto out;
	}
	EMSG("Button %d pressed", button_type);
	params[1].value.a = (button_type == TEE_TUI_VALIDATE);
out:
	free(text);
	return res;
}

static TEE_Result cmd_validate_messages(uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_TUIScreenInfo scr_info;
	TEE_TUIScreenConfiguration scr_cfg;
	TEE_TUIButtonType button_type;
	char *text = NULL;
	size_t n;
	bool done = false;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (exp_pt != param_types || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_TUIGetScreenInfo(TEE_TUI_LANDSCAPE, 2, &scr_info);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIGetScreenInfo: fail %#" PRIx32, res);
		goto out;
	}

	res = TEE_TUIInitSession();
	if (res != TEE_SUCCESS) {
		EMSG("TEE_TUIInitSession: fail %#" PRIx32, res);
		goto out;
	}

	n = 0;
	while (!done) {
		free(text);
		text = strndup(params[n].memref.buffer, params[n].memref.size);
		if (!text)
			return TEE_ERROR_OUT_OF_MEMORY;

		memset(&scr_cfg, 0, sizeof(scr_cfg));
		scr_cfg.screenOrientation = TEE_TUI_LANDSCAPE;
		scr_cfg.label.text = text;
		switch (n) {
		case 0:
			scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
			scr_cfg.requestedButtons[TEE_TUI_NEXT] = true;
			break;
		case 1:
			scr_cfg.requestedButtons[TEE_TUI_PREVIOUS] = true;
			scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
			scr_cfg.requestedButtons[TEE_TUI_NEXT] = true;
			break;
		case 2:
			scr_cfg.requestedButtons[TEE_TUI_PREVIOUS] = true;
			scr_cfg.requestedButtons[TEE_TUI_CANCEL] = true;
			scr_cfg.requestedButtons[TEE_TUI_VALIDATE] = true;
			break;
		default:
			TEE_Panic(0);
		}

		res = TEE_TUIDisplayScreen(&scr_cfg, false, NULL, 0,
					   &button_type);
		if (res != TEE_SUCCESS) {
			EMSG("TEE_TUIDisplayScreen: fail %#" PRIx32, res);
			goto out;
		}
		EMSG("Button %d pressed", button_type);
		switch (button_type) {
		case TEE_TUI_VALIDATE:
		case TEE_TUI_CANCEL:
			done = true;
			break;
		case TEE_TUI_NEXT:
			n++;
			break;
		case TEE_TUI_PREVIOUS:
			n--;
			break;
		default:
			TEE_Panic(1);
		}
	}
	params[3].value.a = (button_type == TEE_TUI_VALIDATE);
out:
	free(text);
	return res;
}

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
			TEE_Param params[TEE_NUM_PARAMS] __unused,
			void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case TA_TUI_CMD_READ_PIN:
		return cmd_read_pin(param_types, params);
	case TA_TUI_CMD_READ_LOGIN:
		return cmd_read_login(param_types, params);
	case TA_TUI_CMD_MESSAGE:
		return cmd_message(param_types, params);
	case TA_TUI_CMD_VALIDATE_MESSAGE:
		return cmd_validate_message(param_types, params);
	case TA_TUI_CMD_VALIDATE_MESSAGES:
		return cmd_validate_messages(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
