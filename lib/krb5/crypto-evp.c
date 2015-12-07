/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2015 PADL Software Pty Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

void
_krb5_evp_schedule(krb5_context context,
		   struct _krb5_key_type *kt,
		   struct _krb5_key_data *kd)
{
    struct _krb5_evp_schedule *key = kd->schedule->data;
    const EVP_CIPHER *c = (*kt->evp)();

    EVP_CIPHER_CTX_init(&key->ectx);
    EVP_CIPHER_CTX_init(&key->dctx);

    EVP_CipherInit_ex(&key->ectx, c, NULL, kd->key->keyvalue.data, NULL, 1);
    EVP_CipherInit_ex(&key->dctx, c, NULL, kd->key->keyvalue.data, NULL, 0);
}

void
_krb5_evp_cleanup(krb5_context context, struct _krb5_key_data *kd)
{
    struct _krb5_evp_schedule *key = kd->schedule->data;
    EVP_CIPHER_CTX_cleanup(&key->ectx);
    EVP_CIPHER_CTX_cleanup(&key->dctx);
}

krb5_error_code
_krb5_evp_encrypt(krb5_context context,
		struct _krb5_key_data *key,
		void *data,
		size_t len,
		krb5_boolean encryptp,
		int usage,
		void *ivec)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;
    c = encryptp ? &ctx->ectx : &ctx->dctx;
    if (ivec == NULL) {
	/* alloca ? */
	size_t len2 = EVP_CIPHER_CTX_iv_length(c);
	void *loiv = malloc(len2);
	if (loiv == NULL)
	    return krb5_enomem(context);
	memset(loiv, 0, len2);
	EVP_CipherInit_ex(c, NULL, NULL, NULL, loiv, -1);
	free(loiv);
    } else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    EVP_Cipher(c, data, data, len);
    return 0;
}

static const unsigned char zero_ivec[EVP_MAX_BLOCK_LENGTH] = { 0 };

krb5_error_code
_krb5_evp_encrypt_cts(krb5_context context,
		      struct _krb5_key_data *key,
		      void *data,
		      size_t len,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    size_t i, blocksize;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH], ivec2[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    unsigned char *p;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);

    if (len < blocksize) {
	krb5_set_error_message(context, EINVAL,
			       "message block too short");
	return EINVAL;
    } else if (len == blocksize) {
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, data, data, len);
	return 0;
    }

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    if (encryptp) {

	p = data;
	i = ((len - 1) / blocksize) * blocksize;
	EVP_Cipher(c, p, p, i);
	p += i - blocksize;
	len -= i;
	memcpy(ivec2, p, blocksize);

	for (i = 0; i < len; i++)
	    tmp[i] = p[i + blocksize] ^ ivec2[i];
	for (; i < blocksize; i++)
	    tmp[i] = 0 ^ ivec2[i];

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, p, tmp, blocksize);

	memcpy(p + blocksize, ivec2, len);
	if (ivec)
	    memcpy(ivec, p, blocksize);
    } else {
	unsigned char tmp2[EVP_MAX_BLOCK_LENGTH], tmp3[EVP_MAX_BLOCK_LENGTH];

	p = data;
	if (len > blocksize * 2) {
	    /* remove last two blocks and round up, decrypt this with cbc, then do cts dance */
	    i = ((((len - blocksize * 2) + blocksize - 1) / blocksize) * blocksize);
	    memcpy(ivec2, p + i - blocksize, blocksize);
	    EVP_Cipher(c, p, p, i);
	    p += i;
	    len -= i + blocksize;
	} else {
	    if (ivec)
		memcpy(ivec2, ivec, blocksize);
	    else
		memcpy(ivec2, zero_ivec, blocksize);
	    len -= blocksize;
	}

	memcpy(tmp, p, blocksize);
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, tmp2, p, blocksize);

	memcpy(tmp3, p + blocksize, len);
	memcpy(tmp3 + len, tmp2 + len, blocksize - len); /* xor 0 */

	for (i = 0; i < len; i++)
	    p[i + blocksize] = tmp2[i] ^ tmp3[i];

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, p, tmp3, blocksize);

	for (i = 0; i < blocksize; i++)
	    p[i] ^= ivec2[i];
	if (ivec)
	    memcpy(ivec, tmp, blocksize);
    }
    return 0;
}

/*
 * This is overloaded to abstract away GCM/CCM differences and does not
 * actually encrypt anything, it just sets IV parameters and gets/sets
 * the tag.
 */
krb5_error_code
_krb5_evp_encrypt_gcm(krb5_context context,
		      struct _krb5_key_data *key,
		      void *data,
		      size_t len,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    const size_t ivecsz = 12;
    unsigned char zeros[12];
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;
    krb5_boolean preludep;

    c = encryptp ? &ctx->ectx : &ctx->dctx;
    preludep = !!data ^ encryptp; /* is being called before encrypt/decrypt */

    if (ivec == NULL) {
	memset(zeros, 0, ivecsz);
	ivec = zeros;
    }

    if (preludep) {
	EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, ivecsz, NULL);
	EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IV_FIXED, -1, ivec);
	if (encryptp) {
	    /* Copy in/out IV from caller (nonce or chained cipherstate) */
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_IV_GEN, ivecsz, ivec);
	} else {
	    /* Copy in IV from caller without incrementing counter */
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IV_INV, ivecsz, ivec);
	    /* Copy in tag for verification */
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, len, data);
	}
    } else {
	/* Copy out ivec to caller, if cipherstate chaining required */
	if (ivec)
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_IV_GEN, ivecsz, ivec);

	/* Copy out tag to caller */
	if (encryptp) {
	    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, len, data) != 1)
		return KRB5_CRYPTO_INTERNAL;
	}
    }

    return 0;
}

static krb5_crypto_iov *
iov_find(krb5_crypto_iov *data, size_t num_data, unsigned type)
{
    size_t i;
    for (i = 0; i < num_data; i++)
	if (data[i].flags == type)
	    return &data[i];
    return NULL;
}

krb5_error_code
_krb5_evp_cipher_aead(krb5_context context,
		      struct _krb5_key_data *dkey,
		      krb5_crypto_iov *data,
		      int num_data,
		      void *ivec,
		      int encryptp)
{
    const struct _krb5_encryption_type *et = _krb5_find_enctype(dkey->key->keytype);
    size_t headersz, trailersz;
    krb5_error_code ret;
    krb5_crypto_iov *tiv, *piv, *hiv;
    struct _krb5_evp_schedule *ctx;
    EVP_CIPHER_CTX *c;
    int i, outlen;

    headersz = et->confoundersize;
    trailersz = et->blocksize;

    /* header */
    hiv = iov_find(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (hiv) {
	if (hiv->data.length != headersz)
	    return KRB5_BAD_MSIZE;
	if (encryptp && headersz)
	    krb5_generate_random_block(hiv->data.data, hiv->data.length);
    }

    /* padding */
    piv = iov_find(data, num_data, KRB5_CRYPTO_TYPE_PADDING);
    if (piv != NULL)
	piv->data.length = 0; /* AEAD modes function as stream ciphers */

    /* trailer */
    tiv = iov_find(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (tiv == NULL || tiv->data.length != trailersz)
	return KRB5_BAD_MSIZE;

    ctx = dkey->schedule->data;
    c = encryptp ? &ctx->ectx : &ctx->dctx;

    /* This API is overloaded just to abstract away GCM/CCM differences */
    ret = (*et->encrypt)(context, dkey,
			 encryptp ? NULL : tiv->data.data,
			 encryptp ? 0 : tiv->data.length,
			 encryptp, 0, ivec);
    if (ret)
	return ret;

    /* Spec/OpenSSL insist associated data comes before plaintext */
    for (i = 0; i < num_data; i++) {
	outlen = data[i].data.length;

	if (data[i].flags != KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    continue;

	if (EVP_CipherUpdate(c, NULL, &outlen,
			     data[i].data.data, data[i].data.length) != 1)
	    return encryptp ? KRB5_CRYPTO_INTERNAL : KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }

    for (i = 0; i < num_data; i++) {
	outlen = data[i].data.length;

	if (data[i].flags != KRB5_CRYPTO_TYPE_DATA)
	    continue;

	if (EVP_CipherUpdate(c, data[i].data.data, &outlen,
			     data[i].data.data, data[i].data.length) != 1)
	    return encryptp ? KRB5_CRYPTO_INTERNAL : KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }

    /* Generates tag */
    if (EVP_CipherUpdate(c, NULL, &outlen, NULL, 0) != 1)
	return encryptp ? KRB5_CRYPTO_INTERNAL : KRB5KRB_AP_ERR_BAD_INTEGRITY;

    ret = (*et->encrypt)(context, dkey,
			 encryptp ? tiv->data.data : NULL,
			 encryptp ? tiv->data.length : 0,
			 encryptp, 0, ivec);
    if (ret)
	return ret;

    return 0;
}
