/*
*
 * This software is
 * Copyright (c) 2015 Michael Kramer <michael.kramer@uni-konstanz.de>,
 * Copyright (c) 2015 magnum
 * Copyright (c) 2016 Fist0urs <eddy.maaalou@gmail.com>
 * slight modifications to support AS-REP responses by @harmj0y
 *
 * Modified by Fist0urs to improve performances by proceeding known-plain
 * attack, based on defined ASN1 structures (then got rid of RC4 rounds
 * + hmac-md5)
 *
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5asrep;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5asrep);
#else

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "dyna_salt.h"
#include "rc4.h"
#include "md4.h"
#include "hmacmd5.h"
#include "unicode.h"
#include "memdbg.h"

#ifndef OMP_SCALE
#define OMP_SCALE		256
#endif

#define FORMAT_LABEL		"krb5asrep"
#define FORMAT_NAME		"Kerberos 5 AS-REP etype 23"
#define FORMAT_TAG           "$krb5asrep$23$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"MD4 HMAC-MD5 RC4"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1000
#define MIN_PLAINTEXT_LENGTH	0
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(struct custom_salt *)
#define SALT_ALIGN		sizeof(struct custom_salt *)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

/*
  assuming checksum == edata1

  formats are:
	 checksum$edata2
	 $krb5asrep$23$checksum$edata2
*/
static struct fmt_tests tests[] = {
	{"63B386C8C75ECD10F9DF354F42427FBF$BB46B57E89D878455743D1E4C2CD871B5A526A130595463CC021510BA476247B8F9431505155CBC3D7E6120E93623E083A6A508111937607B73F8F524C23E482B648A9C1BE74D7B72B230711BF405ACE9CAF01D5FAC0304509F0DE2A43E0A0834D5F4D5683CA1B8164359B28AC91B35025158A6C9AAD2585D54BAA0A7D886AC154A0B00BE77E86F25439B2298E9EDA7D4BCBE84F505C6C4E6477BB2C9FF860D80E69E99F83A8D1205743CCDD7EC3C3B8FEC481FCC688EC3BD4BA60D93EB30A3259B2E9542CC281B25061D298F672009DCCE9DCAF47BB296480F941AFCDA533F13EA99739F97B92C971A7B4FB970F", "Password123!"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_K1)[16];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

static struct custom_salt {
	dyna_salt dsalt;
	unsigned char edata1[16];
	uint32_t edata2len;
	unsigned char* edata2;
} *cur_salt;

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char *ptr, *keeptr;
	int i;

	if (strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;
	ptr = mem_alloc_tiny(strlen(ciphertext) + FORMAT_TAG_LEN + 1, MEM_ALIGN_NONE);
	keeptr = ptr;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0) {
		memcpy(ptr, FORMAT_TAG, FORMAT_TAG_LEN);
		ptr += FORMAT_TAG_LEN;
	}

	for (i = 0; i < strlen(ciphertext) + 1; i++)
		ptr[i] = tolower(ARCH_INDEX(ciphertext[i]));

	return keeptr;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int extra;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0) {
		ctcopy += FORMAT_TAG_LEN;
		if (ctcopy[0] == '*') {			/* assume account's info provided */
			ctcopy++;
			p = strtokm(ctcopy, "*");
			ctcopy  = strtokm(NULL, "");
			if (!ctcopy || *ctcopy != '$')
				goto err;
			++ctcopy;	/* set after '$' */
			goto edata;
		}
		if (ctcopy[0] == '$')
			ctcopy++;
	}

edata:
	/* assume checksum */
	if (((p = strtokm(ctcopy, "$")) == NULL) || strlen(p) != 32)
		goto err;

	/* assume edata2 following */
	if (((p = strtokm(NULL, "$")) == NULL))
		goto err;
	if (!ishex(p) && (hexlen(p, &extra) < 64 || extra))
		goto err;

	if ((strtokm(NULL, "$") != NULL))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_alloc_align(sizeof(*saved_key) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	saved_K1 = mem_alloc_align(sizeof(*saved_K1) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_K1);
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;

	char *p;
	char *ctcopy;
	char *keeptr;
	static void *ptr;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	memset(&cs, 0, sizeof(cs));
	cs.edata2 = NULL;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0) {
		ctcopy += FORMAT_TAG_LEN;
		if (ctcopy[0] == '*') {
			ctcopy++;
			p = strtokm(ctcopy, "*");
			ctcopy += strlen(p) + 2;
			goto edata;
		}
		if (ctcopy[0]=='$')
			ctcopy++;
	}

edata:
	if (((p = strtokm(ctcopy, "$")) != NULL) && strlen(p) == 32) {	/* assume checksum */
		for (i = 0; i < 16; i++) {
			cs.edata1[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}

		/* skip '$' */
		p += strlen(p) + 1;

		/* retrieve non-constant length of edata2 */
		for (i = 0; p[i] != '\0'; i++)
			;
		cs.edata2len = i/2;
		cs.edata2 = (unsigned char*) mem_calloc_tiny(cs.edata2len + 1, sizeof(char));

		for (i = 0; i < cs.edata2len; i++) {	/* assume edata2 */
			cs.edata2[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}

	MEM_FREE(keeptr);

	/* following is used to fool dyna_salt stuff */
	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, edata1);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, edata1, edata2len, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *) &ptr;
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt**)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, strlen(key) + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	// const unsigned char data[4] = {2, 0, 0, 0};
	const unsigned char data[4] = {8, 0, 0, 0};
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif

	for (index = 0; index < count; index++) {
		unsigned char K3[16];
#ifdef _MSC_VER
		unsigned char ddata[65536];
#else
		unsigned char ddata[cur_salt->edata2len + 1];
#endif
		unsigned char checksum[16];
		RC4_KEY rckey;

		if (new_keys) {
			MD4_CTX ctx;
			unsigned char key[16];
			UTF16 wkey[PLAINTEXT_LENGTH + 1];
			int len;

			len = enc_to_utf16(wkey, PLAINTEXT_LENGTH,
					(UTF8*)saved_key[index],
					strlen(saved_key[index]));
			if (len <= 0) {
				saved_key[index][-len] = 0;
				len = strlen16(wkey);
			}

			MD4_Init(&ctx);
			MD4_Update(&ctx, (char*)wkey, 2 * len);
			MD4_Final(key, &ctx);

			hmac_md5(key, data, 4, saved_K1[index]);
		}

		hmac_md5(saved_K1[index], cur_salt->edata1, 16, K3);

		RC4_set_key(&rckey, 16, K3);
		RC4(&rckey, 32, cur_salt->edata2, ddata);

		/* check the checksum */
		RC4(&rckey, cur_salt->edata2len - 32, cur_salt->edata2 + 32, ddata + 32);
		hmac_md5(saved_K1[index], ddata, cur_salt->edata2len, checksum);

		if (!memcmp(checksum, cur_salt->edata1, 16)) {
			cracked[index] = 1;

#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	new_keys = 0;

	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_krb5asrep = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		MIN_PLAINTEXT_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP | FMT_DYNA_SALT,
		{NULL},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{NULL},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif
