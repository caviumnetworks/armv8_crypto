/*
 *   BSD LICENSE
 *
 *   Copyright (C) Cavium networks Ltd. 2016.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Cavium networks nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ARMV8_DEFS_H_
#define _ARMV8_DEFS_H_

#include <stdint.h>

struct crypto_arg {
	struct {
		uint8_t *key;
		uint8_t *iv;
	} cipher;
	struct {
		struct {
			uint8_t *key;
			uint8_t *i_key_pad;
			uint8_t *o_key_pad;
		} hmac;
	} digest;
};

typedef struct crypto_arg crypto_arg_t;

void aes128_key_sched_enc(uint8_t *expanded_key, const uint8_t *user_key);
void aes128_key_sched_dec(uint8_t *expanded_key, const uint8_t *user_key);

int aes128cbc_sha1_hmac(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			crypto_arg_t *arg);
int aes128cbc_sha256_hmac(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			crypto_arg_t *arg);
int sha1_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			crypto_arg_t *arg);
int sha256_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			crypto_arg_t *arg);

int sha1_block_partial(uint8_t *init, const uint8_t *src, uint8_t *dst,
			uint64_t len);
int sha1_block(uint8_t *init, const uint8_t *src, uint8_t *dst, uint64_t len);

int sha256_block_partial(uint8_t *init, const uint8_t *src, uint8_t *dst,
			uint64_t len);
int sha256_block(uint8_t *init, const uint8_t *src, uint8_t *dst, uint64_t len);

#endif /* _ARMV8_DEFS_H_ */
