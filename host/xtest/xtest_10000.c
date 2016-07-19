/*
 * Copyright (c) 2014, Linaro Limited
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
#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <string.h>
#include <enc_fs_key_manager_test.h>
#include <conf.h>
#include <util.h>

#define WITH_HKDF 1
#define WITH_CONCAT_KDF 1
#define WITH_PBKDF2 1

static void xtest_tee_test_10001(ADBG_Case_t *c);
static void xtest_tee_test_10002(ADBG_Case_t *c);

ADBG_CASE_DEFINE(XTEST_TEE_10001, xtest_tee_test_10001,
		 /* Title */
		 "Test TEE Internal API key derivation extensions",
		 /* Short description */
		 "Test non-standard cryptographic key derivation algorithms",
		 /* Requirement IDs */
		 "Linaro CARD-1661",
		 /* How to implement */
		 "Invoke key derivation functions with standard test vectors"
		);

ADBG_CASE_DEFINE(XTEST_TEE_10002, xtest_tee_test_10002,
	/* Title */
	"Secure Storage Key Manager API Self Test",
	/* Short description */
	"Test secure storage key manager functionality",
	/* Requirement IDs */
	"Linaro SWG-176",
	/* How to implement */
	"Invoke key manager self test function in test TA"
	);

/*
 * HKDF test data from RFC 5869
 */

/* A.1 SHA-256 */

static const uint8_t hkdf_a1_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t hkdf_a1_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t hkdf_a1_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9
};

static const uint8_t hkdf_a1_okm[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
	0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
	0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
	0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65
};

/* A.2 SHA-256 */
static const uint8_t hkdf_a2_ikm[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const uint8_t hkdf_a2_salt[] = {
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};

static const uint8_t hkdf_a2_info[] = {
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const uint8_t hkdf_a2_okm[] = {
	0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
	0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
	0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
	0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
	0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
	0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
	0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
	0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
	0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
	0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
	0x1d, 0x87
};

/* A.3 SHA-256 */
#define hkdf_a3_ikm hkdf_a1_ikm
static const uint8_t hkdf_a3_salt[] = {};

static const uint8_t hkdf_a3_info[] = {};

static const uint8_t hkdf_a3_okm[] = {
	0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
	0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
	0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
	0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
	0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
	0x96, 0xc8
};

/* A.4 SHA-1 */
static const uint8_t hkdf_a4_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b
};

static const uint8_t hkdf_a4_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t hkdf_a4_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9
};

static const uint8_t hkdf_a4_okm[] = {
	0x08, 0x5a, 0x01, 0xea, 0x1b, 0x10, 0xf3, 0x69,
	0x33, 0x06, 0x8b, 0x56, 0xef, 0xa5, 0xad, 0x81,
	0xa4, 0xf1, 0x4b, 0x82, 0x2f, 0x5b, 0x09, 0x15,
	0x68, 0xa9, 0xcd, 0xd4, 0xf1, 0x55, 0xfd, 0xa2,
	0xc2, 0x2e, 0x42, 0x24, 0x78, 0xd3, 0x05, 0xf3,
	0xf8, 0x96
};

/* A.5 SHA-1 */
#define hkdf_a5_ikm hkdf_a2_ikm
#define hkdf_a5_salt hkdf_a2_salt
#define hkdf_a5_info hkdf_a2_info
static const uint8_t hkdf_a5_okm[] = {
	0x0b, 0xd7, 0x70, 0xa7, 0x4d, 0x11, 0x60, 0xf7,
	0xc9, 0xf1, 0x2c, 0xd5, 0x91, 0x2a, 0x06, 0xeb,
	0xff, 0x6a, 0xdc, 0xae, 0x89, 0x9d, 0x92, 0x19,
	0x1f, 0xe4, 0x30, 0x56, 0x73, 0xba, 0x2f, 0xfe,
	0x8f, 0xa3, 0xf1, 0xa4, 0xe5, 0xad, 0x79, 0xf3,
	0xf3, 0x34, 0xb3, 0xb2, 0x02, 0xb2, 0x17, 0x3c,
	0x48, 0x6e, 0xa3, 0x7c, 0xe3, 0xd3, 0x97, 0xed,
	0x03, 0x4c, 0x7f, 0x9d, 0xfe, 0xb1, 0x5c, 0x5e,
	0x92, 0x73, 0x36, 0xd0, 0x44, 0x1f, 0x4c, 0x43,
	0x00, 0xe2, 0xcf, 0xf0, 0xd0, 0x90, 0x0b, 0x52,
	0xd3, 0xb4
};

/* A.6 SHA-1 */
#define hkdf_a6_ikm hkdf_a1_ikm
static const uint8_t hkdf_a6_salt[] = {};

static const uint8_t hkdf_a6_info[] = {};

static const uint8_t hkdf_a6_okm[] = {
	0x0a, 0xc1, 0xaf, 0x70, 0x02, 0xb3, 0xd7, 0x61,
	0xd1, 0xe5, 0x52, 0x98, 0xda, 0x9d, 0x05, 0x06,
	0xb9, 0xae, 0x52, 0x05, 0x72, 0x20, 0xa3, 0x06,
	0xe0, 0x7b, 0x6b, 0x87, 0xe8, 0xdf, 0x21, 0xd0,
	0xea, 0x00, 0x03, 0x3d, 0xe0, 0x39, 0x84, 0xd3,
	0x49, 0x18
};

/* A.7 SHA-1 */
static const uint8_t hkdf_a7_ikm[] = {
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
};

static const uint8_t hkdf_a7_salt[] = {};

static const uint8_t hkdf_a7_info[] = {};

static const uint8_t hkdf_a7_okm[] = {
	0x2c, 0x91, 0x11, 0x72, 0x04, 0xd7, 0x45, 0xf3,
	0x50, 0x0d, 0x63, 0x6a, 0x62, 0xf6, 0x4f, 0x0a,
	0xb3, 0xba, 0xe5, 0x48, 0xaa, 0x53, 0xd4, 0x23,
	0xb0, 0xd1, 0xf2, 0x7e, 0xbb, 0xa6, 0xf5, 0xe5,
	0x67, 0x3a, 0x08, 0x1d, 0x70, 0xcc, 0xe7, 0xac,
	0xfc, 0x48
};

/*
 * Concat KDF (NIST SP 800-56A R1)
 *
 * Test vector from:
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37
 * appendix C
 */
static const uint8_t concat_kdf_1_z[] = {
	158, 86, 217, 29, 129, 113, 53, 211,
	114, 131, 66, 131, 191, 132, 38, 156,
	251, 49, 110, 163, 218, 128, 106, 72,
	246, 218, 167, 121, 140, 254, 144, 196
};

static const uint8_t concat_kdf_1_other_info[] = {
	0, 0, 0, 7, 65, 49, 50, 56,
	71, 67, 77, 0, 0, 0, 5, 65,
	108, 105, 99, 101, 0, 0, 0, 3,
	66, 111, 98, 0, 0, 0, 128
};

static const uint8_t concat_kdf_1_derived_key[] = {
	86, 170, 141, 234, 248, 35, 109, 32,
	92, 34, 40, 205, 113, 167, 16, 26
};

/*
 * PKCS #5 2.0 / RFC 2898 Key Derivation Function 2 (PBKDF2)
 * Test vectors from RFC 6070 https://www.ietf.org/rfc/rfc6070.txt
 */

/* 1 */
static const uint8_t pbkdf2_1_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_1_salt[] = {
	's', 'a', 'l', 't'
};

#define pbkdf2_1_iteration_count 1
static const uint8_t pbkdf2_1_dkm[] = {
	0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
	0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
	0x2f, 0xe0, 0x37, 0xa6
};

/* 2 */
#define pbkdf2_2_password pbkdf2_1_password
#define pbkdf2_2_salt pbkdf2_1_salt
#define pbkdf2_2_iteration_count 2
static const uint8_t pbkdf2_2_dkm[] = {
	0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
	0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
	0xd8, 0xde, 0x89, 0x57
};

/* 3 */
#define pbkdf2_3_password pbkdf2_1_password
#define pbkdf2_3_salt pbkdf2_1_salt
#define pbkdf2_3_iteration_count 4096
static const uint8_t pbkdf2_3_dkm[] = {
	0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
	0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
	0x65, 0xa4, 0x29, 0xc1
};

/* 4 */
#define pbkdf2_4_password pbkdf2_1_password
#define pbkdf2_4_salt pbkdf2_1_salt
#define pbkdf2_4_iteration_count 16777216
static const uint8_t pbkdf2_4_dkm[] = {
	0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
	0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
	0x26, 0x34, 0xe9, 0x84
};

/* 5 */
static const uint8_t pbkdf2_5_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_5_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_5_iteration_count 4096
static const uint8_t pbkdf2_5_dkm[] = {
	0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
	0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
	0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
	0x38
};

/* 6 */
static const uint8_t pbkdf2_6_password[] = {
	'p', 'a', 's', 's', '\0', 'w', 'o', 'r',
	'd',
};

static const uint8_t pbkdf2_6_salt[] = {
	's', 'a', '\0', 'l', 't'
};

#define pbkdf2_6_iteration_count 4096
static const uint8_t pbkdf2_6_dkm[] = {
	0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
	0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
};

/*
 * Scrypt test data from
 * https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00
 */

/*
 *  scrypt (P="", S="",
 *           r=16, N=1, p=1, dklen=64) =
 *   77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
 *   f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
 *   fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
 *   e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
 */

/* Using 2496 bytes of working memory */
static const uint8_t scrypt_1_passwd[] = "";
#define scrypt_1_passwd_size	(sizeof(scrypt_1_passwd) - 1)
#define scrypt_1_salt		NULL
#define scrypt_1_salt_size	0
#define scrypt_1_N		16
#define scrypt_1_r		1
#define scrypt_1_p		1
static const uint8_t scrypt_1_dk[] = {
	0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
	0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
	0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
	0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
	0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
	0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
	0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
	0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
};

/*
 * Scrypt test data generated with:
 * scrypt_vectors.py --passwd "letmein" --salt "12345" --N 16 --r 1 --p 1 \
 *		     --dklen 64
 */

/* Using 2496 bytes of working memory */
static const uint8_t scrypt_2_passwd[] = "letmein";
#define scrypt_2_passwd_size	(sizeof(scrypt_2_passwd) - 1)
static const uint8_t scrypt_2_salt[] = "12345";
#define scrypt_2_salt_size	(sizeof(scrypt_2_salt) - 1)
#define scrypt_2_N		16
#define scrypt_2_r		1
#define scrypt_2_p		1
static const uint8_t scrypt_2_dk[] = {
	0xbe, 0xb9, 0x85, 0xbc, 0xce, 0xe1, 0xf9, 0x03,
	0x6f, 0x9b, 0x96, 0x10, 0x6b, 0x2c, 0xa7, 0xab,
	0x96, 0xb4, 0x10, 0xe3, 0x41, 0x99, 0xaa, 0x44,
	0x09, 0x07, 0x93, 0xb0, 0xda, 0x06, 0x7b, 0x90,
	0x76, 0x19, 0xa7, 0x19, 0xe2, 0xb6, 0x7c, 0x21,
	0x9f, 0xd7, 0xfe, 0xea, 0xf7, 0x69, 0x2e, 0x5d,
	0xfe, 0x92, 0x64, 0x61, 0xf2, 0xe7, 0xca, 0x32,
	0x0d, 0x71, 0x45, 0x8a, 0xca, 0x31, 0x6e, 0x0a,
};

/*
 * Scrypt test data generated with:
 * scrypt_vectors.py --passwd "letmein" --salt "12345" --N 16 --r 1 --p 8 \
 *		     --dklen 64
 */

/* Using 3392 bytes of working memory */
static const uint8_t scrypt_3_passwd[] = "letmein";
#define scrypt_3_passwd_size	(sizeof(scrypt_3_passwd) - 1)
static const uint8_t scrypt_3_salt[] = "12345";
#define scrypt_3_salt_size	(sizeof(scrypt_3_salt) - 1)
#define scrypt_3_N		16
#define scrypt_3_r		1
#define scrypt_3_p		8
static const uint8_t scrypt_3_dk[] = {
	0x1c, 0xf1, 0x38, 0x43, 0x5c, 0xd6, 0x21, 0xd2,
	0xfb, 0xdd, 0xe0, 0xb6, 0x45, 0xff, 0xfe, 0xf1,
	0x0a, 0x2c, 0xa0, 0x98, 0xb2, 0xf6, 0xd2, 0x96,
	0x49, 0x9b, 0x38, 0x54, 0x27, 0xfb, 0xf5, 0xff,
	0x9d, 0x55, 0x37, 0x4d, 0x6a, 0xb8, 0x85, 0x3a,
	0x6b, 0x64, 0xea, 0xe0, 0xfe, 0x34, 0x8f, 0xca,
	0x8b, 0x75, 0xb0, 0x59, 0xcd, 0x90, 0x33, 0x9a,
	0x06, 0x12, 0xa8, 0xc3, 0xdf, 0x44, 0x0c, 0xd4,
};

/*
 * Scrypt test data generated with:
 * scrypt_vectors.py --passwd "letmein" --salt "12345" --N 16 --r 4 --p 8 \
 *		     --dklen 64
 */

/* Using 13376 bytes of working memory */
static const uint8_t scrypt_4_passwd[] = "letmein";
#define scrypt_4_passwd_size	(sizeof(scrypt_4_passwd) - 1)
static const uint8_t scrypt_4_salt[] = "12345";
#define scrypt_4_salt_size	(sizeof(scrypt_4_salt) - 1)
#define scrypt_4_N		16
#define scrypt_4_r		4
#define scrypt_4_p		8
static const uint8_t scrypt_4_dk[] = {
	0xe0, 0x53, 0x53, 0x48, 0xd8, 0x87, 0xf9, 0xb5,
	0x15, 0xd1, 0x1a, 0xbb, 0x12, 0x9c, 0xf1, 0x84,
	0xd2, 0x82, 0x93, 0x2a, 0x9a, 0x03, 0x7c, 0xd1,
	0x8f, 0x22, 0x31, 0x4d, 0xc2, 0x3e, 0x01, 0x63,
	0xc3, 0x28, 0x1e, 0x2c, 0xc7, 0xf2, 0x29, 0xb6,
	0x82, 0x0f, 0x42, 0xe7, 0x19, 0x70, 0x56, 0x4d,
	0x8e, 0x63, 0x1f, 0xf2, 0x22, 0xd5, 0x7f, 0x31,
	0xd9, 0xa7, 0x77, 0x39, 0xdb, 0xb0, 0x52, 0x14,
};

/*
 * Scrypt test data generated with:
 * scrypt_vectors.py --passwd "mypassword" --salt "mysalt" --N 4 --r 29 --p 1 \
 *		     --dklen 128
 */

/* Using 26048 bytes of working memory */
static const uint8_t scrypt_5_passwd[] = "mypassword";
#define scrypt_5_passwd_size	(sizeof(scrypt_5_passwd) - 1)
static const uint8_t scrypt_5_salt[] = "mysalt";
#define scrypt_5_salt_size	(sizeof(scrypt_5_salt) - 1)
#define scrypt_5_N		4
#define scrypt_5_r		29
#define scrypt_5_p		1
static const uint8_t scrypt_5_dk[] = {
	0x62, 0x15, 0x6d, 0xc2, 0xbb, 0xc6, 0xc1, 0x93,
	0xf5, 0xde, 0x0a, 0x6b, 0xaf, 0xa9, 0x59, 0x5d,
	0x9f, 0xdd, 0x35, 0x17, 0x01, 0xba, 0xe0, 0xf4,
	0x62, 0xf9, 0x0a, 0x53, 0x67, 0xe1, 0x74, 0x0a,
	0x5a, 0xf5, 0xe9, 0x01, 0xe3, 0x3d, 0x5b, 0x08,
	0x17, 0x25, 0xc6, 0xf2, 0x4d, 0x8c, 0xf2, 0x74,
	0xca, 0x4d, 0x6d, 0x93, 0x92, 0x8b, 0x70, 0xbd,
	0x42, 0x87, 0x65, 0x84, 0x12, 0x29, 0xcb, 0x69,
	0x33, 0xb6, 0x6b, 0x39, 0x17, 0x2d, 0xf4, 0x96,
	0xfa, 0xef, 0x64, 0x92, 0xd2, 0x0a, 0x5b, 0x63,
	0x86, 0xd0, 0x4c, 0x3a, 0xfa, 0xda, 0x26, 0x9e,
	0xda, 0x88, 0x6b, 0x33, 0xc0, 0x2d, 0xdb, 0x45,
	0x9d, 0xce, 0x5f, 0x11, 0x49, 0x60, 0xe5, 0xfb,
	0xcd, 0xd1, 0xb8, 0x9f, 0x38, 0xf4, 0x1a, 0x72,
	0x71, 0x09, 0x46, 0xdb, 0xa0, 0x93, 0x5c, 0xad,
	0x17, 0xb2, 0x33, 0x1e, 0xa1, 0x9b, 0xed, 0x96,
};

#ifdef WITH_HKDF
static void xtest_test_derivation_hkdf(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
#define TEST_HKDF_DATA(section, algo, id, oeb /* omit empty bufs */) \
	{ \
		section, algo, \
		hkdf_##id##_ikm, sizeof(hkdf_##id##_ikm), \
		(oeb && !sizeof(hkdf_##id##_salt)) ? NULL : hkdf_##id##_salt, sizeof(hkdf_##id##_salt), \
		(oeb && !sizeof(hkdf_##id##_info)) ? NULL : hkdf_##id##_info, sizeof(hkdf_##id##_info), \
		hkdf_##id##_okm, sizeof(hkdf_##id##_okm), \
	}
	static struct hkdf_case {
		const char *subcase_name;
		uint32_t algo;
		const uint8_t *ikm;
		size_t ikm_len;
		const uint8_t *salt;
		size_t salt_len;
		const uint8_t *info;
		size_t info_len;
		const uint8_t *okm;
		size_t okm_len;
	} hkdf_cases[] = {
		TEST_HKDF_DATA("A.1 (SHA-256)",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a1, false),
		TEST_HKDF_DATA("A.2 (SHA-256)",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a2, false),
		TEST_HKDF_DATA("A.3 (SHA-256) [1]",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a3, false),
		TEST_HKDF_DATA("A.3 (SHA-256) [2]",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a3, true),
		TEST_HKDF_DATA("A.4 (SHA-1)",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a4, false),
		TEST_HKDF_DATA("A.5 (SHA-1)",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a5, false),
		TEST_HKDF_DATA("A.6 (SHA-1) [1]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a6, false),
		TEST_HKDF_DATA("A.6 (SHA-1) [2]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a6, true),
		TEST_HKDF_DATA("A.7 (SHA-1) [1]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a7, false),
		TEST_HKDF_DATA("A.7 (SHA-1) [2]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a7, true),
	};
	size_t max_size = 2048;

	for (n = 0; n < sizeof(hkdf_cases) / sizeof(struct hkdf_case); n++) {
		TEE_OperationHandle op;
		TEE_ObjectHandle key_handle;
		TEE_ObjectHandle sv_handle;
		TEE_Attribute params[4];
		size_t param_count = 0;
		uint8_t out[2048];
		size_t out_size;
		const struct hkdf_case *hc = &hkdf_cases[n];

		Do_ADBG_BeginSubCase(c, "HKDF RFC 5869 %s", hc->subcase_name);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				hc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_HKDF_IKM, max_size, &key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_IKM, hc->ikm,
			       hc->ikm_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, hc->okm_len * 8,
				&sv_handle)))
			goto out;

		param_count = 0;

		if (hc->salt)
			xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_SALT,
				hc->salt, hc->salt_len);
		if (hc->info)
			xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_INFO,
				hc->info, hc->info_len);

		params[param_count].attributeID = TEE_ATTR_HKDF_OKM_LENGTH;
		params[param_count].content.value.a = hc->okm_len;
		params[param_count].content.value.b = 0;
		param_count++;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, hc->okm, hc->okm_len, out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
	out:
		Do_ADBG_EndSubCase(c, "HKDF RFC 5869 %s", hc->subcase_name);
	}
}
#endif /* WITH_HKDF */

#ifdef WITH_CONCAT_KDF
static void xtest_test_derivation_concat_kdf(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
#define TEST_CONCAT_KDF_DATA(name, algo, id, oeb /* omit empty bufs */) \
	{ \
		name, algo, \
		concat_kdf_##id##_z, sizeof(concat_kdf_##id##_z), \
		(oeb && !sizeof(concat_kdf_##id##_other_info)) ? NULL \
							       : concat_kdf_##id##_other_info, \
		sizeof(concat_kdf_##id##_other_info), \
		concat_kdf_##id##_derived_key, sizeof(concat_kdf_##id##_derived_key), \
	}
	static struct concat_kdf_case {
		const char *subcase_name;
		uint32_t algo;
		const uint8_t *shared_secret;
		size_t shared_secret_len;
		const uint8_t *other_info;
		size_t other_info_len;
		const uint8_t *derived_key;
		size_t derived_key_len;
	} concat_kdf_cases[] = {
		TEST_CONCAT_KDF_DATA("JWA-37 C (SHA-256)",
			TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY, 1, false),
	};
	size_t max_size = 2048;

	for (n = 0;
	     n < sizeof(concat_kdf_cases) / sizeof(struct concat_kdf_case);
	     n++) {
		TEE_OperationHandle op;
		TEE_ObjectHandle key_handle;
		TEE_ObjectHandle sv_handle;
		TEE_Attribute params[4];
		size_t param_count = 0;
		uint8_t out[2048];
		size_t out_size;
		const struct concat_kdf_case *cc = &concat_kdf_cases[n];

		Do_ADBG_BeginSubCase(c, "Concat KDF %s", cc->subcase_name);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				cc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_CONCAT_KDF_Z, max_size, &key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_CONCAT_KDF_Z,
			       cc->shared_secret, cc->shared_secret_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, cc->derived_key_len *
				8, &sv_handle)))
			goto out;

		param_count = 0;

		if (cc->other_info)
			xtest_add_attr(&param_count, params,
				       TEE_ATTR_CONCAT_KDF_OTHER_INFO,
				       cc->other_info, cc->other_info_len);

		params[param_count].attributeID = TEE_ATTR_CONCAT_KDF_DKM_LENGTH;
		params[param_count].content.value.a = cc->derived_key_len;
		params[param_count].content.value.b = 0;
		param_count++;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, cc->derived_key, cc->derived_key_len,
					out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
out:
		Do_ADBG_EndSubCase(c, "Concat KDF %s", cc->subcase_name);
	}
}
#endif /* WITH_CONCAT_KDF */

#ifdef WITH_PBKDF2
static void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
#define TEST_PBKDF2_DATA(section, algo, id, oeb /* omit empty bufs */) \
	{ \
		section, algo, \
		pbkdf2_##id##_password, sizeof(pbkdf2_##id##_password), \
		(oeb && !sizeof(pbkdf2_##id##_salt)) ? NULL : pbkdf2_##id##_salt, sizeof(pbkdf2_##id##_salt), \
		pbkdf2_##id##_iteration_count, \
		pbkdf2_##id##_dkm, sizeof(pbkdf2_##id##_dkm), \
	}
#define RFC6070_TEST(n) \
	TEST_PBKDF2_DATA("RFC 6070 " TO_STR(n) " (HMAC-SHA1)", \
			 TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY, n, false)
	static struct pbkdf2_case {
		const char *subcase_name;
		uint32_t algo;
		const uint8_t *password;
		size_t password_len;
		const uint8_t *salt;
		size_t salt_len;
		uint32_t iteration_count;
		const uint8_t *dkm;
		size_t dkm_len;
	} pbkdf2_cases[] = {
		RFC6070_TEST(1), RFC6070_TEST(2), RFC6070_TEST(3),
#if 0
		RFC6070_TEST(4), /* Lengthy! (3 min on my PC / QEMU) */
#endif
		RFC6070_TEST(5), RFC6070_TEST(6)
	};
	size_t max_size = 2048;

	for (n = 0; n < sizeof(pbkdf2_cases) / sizeof(struct pbkdf2_case); n++) {
		TEE_OperationHandle op;
		TEE_ObjectHandle key_handle;
		TEE_ObjectHandle sv_handle;
		TEE_Attribute params[4];
		size_t param_count = 0;
		uint8_t out[2048];
		size_t out_size;
		const struct pbkdf2_case *pc = &pbkdf2_cases[n];

		Do_ADBG_BeginSubCase(c, "PBKDF2 %s", pc->subcase_name);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				pc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_PBKDF2_PASSWORD, max_size,
				&key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_PBKDF2_PASSWORD,
			       pc->password, pc->password_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, pc->dkm_len * 8,
				&sv_handle)))
			goto out;

		param_count = 0;

		if (pc->salt)
			xtest_add_attr(&param_count, params,
				       TEE_ATTR_PBKDF2_SALT, pc->salt,
				       pc->salt_len);

		params[param_count].attributeID = TEE_ATTR_PBKDF2_DKM_LENGTH;
		params[param_count].content.value.a = pc->dkm_len;
		params[param_count].content.value.b = 0;
		param_count++;

		params[param_count].attributeID =
			TEE_ATTR_PBKDF2_ITERATION_COUNT;
		params[param_count].content.value.a = pc->iteration_count;
		params[param_count].content.value.b = 0;
		param_count++;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out, &out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, pc->dkm, pc->dkm_len, out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
out:
		Do_ADBG_EndSubCase(c, "PBKDF2 %s", pc->subcase_name);
	}
}
#endif /* WITH_PBKDF2 */


#ifdef CFG_CRYPTO_SCRYPT
static void xtest_test_derivation_scrypt(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
#define TEST_SCRYPT_DATA(_id)\
	{ \
		.id = _id, \
		.passwd = scrypt_##_id##_passwd, \
		.passwd_size = scrypt_##_id##_passwd_size, \
		.salt = scrypt_##_id##_salt, \
		.salt_size = scrypt_##_id##_salt_size, \
		.dk = scrypt_##_id##_dk, \
		.dk_size = sizeof(scrypt_##_id##_dk), \
		.N = scrypt_##_id##_N, \
		.r = scrypt_##_id##_r, \
		.p = scrypt_##_id##_p, \
	}
	static struct scrypt_case {
		size_t id;
		const uint8_t *passwd;
		size_t passwd_size;
		const uint8_t *salt;
		size_t salt_size;
		const uint8_t *dk;
		size_t dk_size;
		size_t N;
		size_t r;
		size_t p;
	} scrypt_cases[] = {
		TEST_SCRYPT_DATA(1),
		TEST_SCRYPT_DATA(2),
		TEST_SCRYPT_DATA(3),
		TEST_SCRYPT_DATA(4),
		TEST_SCRYPT_DATA(5),
	};

	for (n = 0; n < ARRAY_SIZE(scrypt_cases); n++) {
		TEE_OperationHandle op;
		TEE_ObjectHandle key_handle;
		TEE_ObjectHandle sv_handle;
		TEE_Attribute attrs[6];
		size_t attr_count = 0;
		uint8_t out[2048];
		size_t out_size;
		size_t max_size = 2048;
		const struct scrypt_case *sc = scrypt_cases + n;

		Do_ADBG_BeginSubCase(c, "Scrypt vector %zu", sc->id);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				TEE_ALG_SCRYPT_DERIVE_KEY, TEE_MODE_DERIVE,
				max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_SCRYPT, max_size, &key_handle)))
			goto out;

		xtest_add_attr(&attr_count, attrs, TEE_ATTR_SCRYPT_PASSWORD,
			       sc->passwd, sc->passwd_size);
		xtest_add_attr_value(&attr_count, attrs, TEE_ATTR_SCRYPT_N,
				     sc->N, 0);
		xtest_add_attr_value(&attr_count, attrs, TEE_ATTR_SCRYPT_R,
				     sc->r, 0);
		xtest_add_attr_value(&attr_count, attrs, TEE_ATTR_SCRYPT_P,
				     sc->p, 0);


		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, attrs, attr_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, sc->dk_size * 8,
				&sv_handle)))
			goto out;

		attr_count = 0;
		if (sc->salt)
			xtest_add_attr(&attr_count, attrs, TEE_ATTR_SCRYPT_SALT,
				       sc->salt, sc->salt_size);
		xtest_add_attr_value(&attr_count, attrs,
				     TEE_ATTR_SCRYPT_DK_LENGTH, sc->dk_size, 0);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						attrs, attr_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out, &out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, sc->dk, sc->dk_size, out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
out:
		Do_ADBG_EndSubCase(c, "Scrypt vector %zu", sc->id);
	}
}
#endif /* CFG_CRYPTO_SCRYPT */

static TEEC_Result enc_fs_km_self_test(TEEC_Session *sess)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t org;

	memset(&op, 0, sizeof(op));
	res = TEEC_InvokeCommand(sess, CMD_SELF_TESTS, &op, &org);
	return res;
}

static void xtest_tee_test_10001(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

#ifdef WITH_HKDF
	xtest_test_derivation_hkdf(c, &session);
#endif
#ifdef WITH_CONCAT_KDF
	xtest_test_derivation_concat_kdf(c, &session);
#endif
#ifdef WITH_PBKDF2
	xtest_test_derivation_pbkdf2(c, &session);
#endif
#ifdef CFG_CRYPTO_SCRYPT
	xtest_test_derivation_scrypt(c, &session);
#endif

	TEEC_CloseSession(&session);
}

/* secure storage key manager self test */
static void xtest_tee_test_10002(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;

	res = xtest_teec_open_session(&sess,
			&enc_fs_key_manager_test_ta_uuid,
			NULL, &orig);
	if (res != TEEC_SUCCESS) {
		Do_ADBG_Log("Ignore test due to TA does not exist");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, enc_fs_km_self_test(&sess)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}
