/*
 * Copyright (c) 2015, PADL Software Pty Ltd.
 * All rights reserved.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

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

    /* AEAD etypes require initialization vectors */
    if (ivec == NULL)
	return KRB5_PROG_ETYPE_NOSUPP;

    headersz = et->confoundersize;
    trailersz = et->blocksize;

    /* header */
    hiv = iov_find(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (hiv) {
	if (hiv->data.length != headersz)
	    return KRB5_BAD_MSIZE;
	if (encryptp)
	    memset(hiv->data.data, 0, hiv->data.length);
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
	    goto failure;
    }

    for (i = 0; i < num_data; i++) {
	outlen = data[i].data.length;

	if (data[i].flags != KRB5_CRYPTO_TYPE_DATA)
	    continue;

	if (EVP_CipherUpdate(c, data[i].data.data, &outlen,
			     data[i].data.data, data[i].data.length) != 1)
	    goto failure;
    }

    /* Generates tag */
    if (EVP_CipherFinal_ex(c, NULL, &outlen) != 1)
	goto failure;

    ret = (*et->encrypt)(context, dkey,
			 encryptp ? tiv->data.data : NULL,
			 encryptp ? tiv->data.length : 0,
			 encryptp, 0, ivec);
    if (ret)
	return ret;

    return 0;

failure:
    return encryptp ? KRB5_CRYPTO_INTERNAL : KRB5KRB_AP_ERR_BAD_INTEGRITY;
}
