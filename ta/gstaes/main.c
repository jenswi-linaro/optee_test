// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 */

#include <assert.h>
#include <ta_gstaes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <utee_defines.h>

static TEE_OperationHandle cipher_oph;
static bool cipher_per_buffer_padding;

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
				    void **ctx)
{
	(void)param_types;
	(void)params;
	(void)ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *ctx)
{
	(void)ctx;
}

static TEE_Result dec_cipher_init(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE);
	TEE_Attribute attr = {
		.attributeID = TEE_ATTR_SECRET_VALUE,
	};
	TEE_ObjectHandle k = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t max_key_size = 0;
	size_t key_size = 0;
	size_t iv_size = 0;
	void *key = NULL;
	void *iv = NULL;

	if (param_types != exp_pt) {
		EMSG("TEE_ERROR_BAD_PARAMETERS");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cipher_oph) {
		TEE_FreeOperation(cipher_oph);
		cipher_oph = TEE_HANDLE_NULL;
	}

	cipher_per_buffer_padding = params[0].value.b;
	key = params[1].memref.buffer;
	max_key_size = params[1].memref.size;
	iv_size = params[2].memref.size;
	iv = params[2].memref.buffer;

	switch (params[0].value.a) {
	case 0: /* GST_AES_CIPHER_128_CBC */
		key_size = 128 / 8;
		break;
	case 1: /* GST_AES_CIPHER_256_CBC */
		key_size = 256 / 8;
		break;
	default:
		EMSG("Invalid cipher %"PRIu32, params[0].value.a);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (key_size > max_key_size) {
		EMSG("Invalid key_size %zu (max %zu)", key_size * 8,
		     max_key_size * 8);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (iv_size != TEE_AES_BLOCK_SIZE) {
		EMSG("Invalid iv_size %zu (expected %zu)", iv_size,
		     TEE_AES_BLOCK_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size * 8, &k);
	if (res) {
		EMSG("TEE_AllocateOperation key_size %zu %#"PRIx32,
		     key_size * 8, res);
		return res;
	}

	res = TEE_AllocateOperation(&cipher_oph, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_DECRYPT, key_size * 8);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT, %zu %#"PRIx32")",
		     key_size * 8, res);
		goto err_free_key;
	}

	attr.content.ref.buffer = key;
	attr.content.ref.length = key_size;
	res = TEE_PopulateTransientObject(k, &attr, 1);
	if (res) {
		EMSG("TEE_PopulateTransientObject key_size %zu %#"PRIx32,
		     key_size * 8, res);
		goto err_free_op;
	}

	res = TEE_SetOperationKey(cipher_oph, k);
	if (res) {
		EMSG("TEE_SetOperationKey %#"PRIx32, res);
		goto err_free_op;
	}

	TEE_CipherInit(cipher_oph, iv, iv_size);
	TEE_FreeTransientObject(k);
	return TEE_SUCCESS;

err_free_op:
	TEE_FreeOperation(cipher_oph);
	cipher_oph = TEE_HANDLE_NULL;
err_free_key:
	TEE_FreeTransientObject(k);
	return res;
}

static TEE_Result remove_padding(uint8_t *buf, size_t *blen)
{
	uint8_t padding = 0;
	size_t l = *blen;
	size_t n = 0;

	assert(l);
	padding = buf[l - 1];
	if (!padding || padding > TEE_AES_BLOCK_SIZE) {
		EMSG("Corrupt cipher text, illegal PKCS7 padding value %"PRIu8,
		     padding);
		return TEE_ERROR_SECURITY;
	}

	for (n = 1; n < padding; n++) {
		if (buf[l - 1 - n] != padding) {
			EMSG("Corrupt cipher text, PKCS7 padding values must all be equal");
			return TEE_ERROR_SECURITY;
		}
	}

	/* Remove padding */
	*blen = l - padding;
	return TEE_SUCCESS;
}

static TEE_Result dec_cipher_update(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_pt || !params[0].memref.size) {
		EMSG("TEE_ERROR_BAD_PARAMETERS");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					  TEE_MEMORY_ACCESS_SECURE,
					  params[1].memref.buffer,
					  params[1].memref.size);
	if (res) {
		EMSG("TEE_CheckMemoryAccessRights(%p, %#zx %#"PRIx32")",
		     params[1].memref.buffer, params[1].memref.size, res);
		return res;
	}

	res = TEE_CipherUpdate(cipher_oph, params[0].memref.buffer,
			       params[0].memref.size, params[1].memref.buffer,
			       &params[1].memref.size);
	if (res) {
		EMSG("TEE_CipherUpdate %#"PRIx32, res);
		return res;
	}
	if (cipher_per_buffer_padding)
		res = remove_padding(params[1].memref.buffer,
				     &params[1].memref.size);
	if (!res) {
		res = TEE_CacheClean(params[1].memref.buffer,
				     params[1].memref.size);
		if (res)
			EMSG("TEE_CacheClean(%p, %#zx %#"PRIx32")",
			     params[1].memref.buffer, params[1].memref.size,
			     res);
	}

	return res;
}

static TEE_Result dec_cipher_final(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_pt) {
		EMSG("TEE_ERROR_BAD_PARAMETERS");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					  TEE_MEMORY_ACCESS_SECURE,
					  params[0].memref.buffer,
					  params[0].memref.size);
	if (res) {
		EMSG("TEE_CheckMemoryAccessRights(%p, %#zx %#"PRIx32")",
		     params[0].memref.buffer, params[0].memref.size, res);
		return res;
	}

	res = TEE_CipherDoFinal(cipher_oph, NULL, 0, params[1].memref.buffer,
				&params[1].memref.size);
	if (res) {
		EMSG("TEE_CipherDoFinal %#"PRIx32, res);
		return res;
	}

	res = TEE_CacheClean(params[1].memref.buffer, params[1].memref.size);
	if (res)
		EMSG("TEE_CacheClean(%p, %#zx %#"PRIx32")",
		     params[1].memref.buffer, params[1].memref.size, res);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *ctx, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	(void)ctx;

	switch (cmd) {
	case TA_GSTAES_DEC_CIPHER_INIT:
		return dec_cipher_init(param_types, params);
	case TA_GSTAES_DEC_CIPHER_UPDATE:
		return dec_cipher_update(param_types, params);
	case TA_GSTAES_DEC_CIPHER_FINAL:
		return dec_cipher_final(param_types, params);
	default:
		EMSG("TEE_ERROR_BAD_PARAMETERS");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
