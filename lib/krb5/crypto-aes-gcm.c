/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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

/*
 * AES GCM
 */

static struct _krb5_key_type keytype_aes128_gcm = {
    KRB5_ENCTYPE_AES128_GCM_128,
    "aes-128-gcm",
    128,
    16,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_128_gcm
};

static struct _krb5_key_type keytype_aes256_gcm = {
    KRB5_ENCTYPE_AES256_GCM_128,
    "aes-256-gcm",
    256,
    32,
    sizeof(struct _krb5_evp_schedule),
    NULL,
    _krb5_evp_schedule,
    NULL,
    NULL,
    _krb5_evp_cleanup,
    EVP_aes_256_gcm
};

struct _krb5_checksum_type _krb5_checksum_gmac_128_aes128 = {
    CKSUMTYPE_GMAC_128_AES128,
    "gmac-128-aes128",
    128,
    28, /* checksum is 28 bytes because it has 12 byte nonce */
    F_KEYED | F_CPROOF | F_DERIVED | F_AEAD,
    _krb5_create_checksum_aead,
    _krb5_verify_checksum_aead
};

struct _krb5_checksum_type _krb5_checksum_gmac_128_aes256 = {
    CKSUMTYPE_GMAC_128_AES256,
    "gmac-128-aes256",
    128,
    28, /* checksum is 28 bytes because it has 12 byte nonce */
    F_KEYED | F_CPROOF | F_DERIVED | F_AEAD,
    _krb5_create_checksum_aead,
    _krb5_verify_checksum_aead
};

static krb5_error_code
AES_GMAC_PRF(krb5_context context,
	     krb5_crypto crypto,
	     const krb5_data *in,
	     krb5_data *out)
{
    krb5_error_code ret;
    krb5_data label;
    const EVP_CIPHER *c = (*crypto->et->keytype->evp)();

    ret = krb5_data_alloc(&label, 3 + in->length);
    if (ret)
	return ret;

    memcpy(label.data, "prf", 3);
    memcpy((unsigned char *)label.data + 3, in->data, in->length);

    ret = krb5_data_alloc(out, crypto->et->blocksize);
    if (ret) {
	krb5_data_free(&label);
	return ret;
    }

    ret = _krb5_SP800_108_KDF_cipher(context, &crypto->key.key->keyvalue,
				     &label, NULL, c, out);

    if (ret)
	krb5_data_free(out);
    krb5_data_free(&label);

    return ret;
}

struct _krb5_encryption_type _krb5_enctype_aes128_gcm_128 = {
    ETYPE_AES128_GCM_128,
    "aes128-gcm-128",
    "aes128-gcm-128",
    16,
    1,
    12,
    &keytype_aes128_gcm,
    NULL, /* should never be called */
    &_krb5_checksum_gmac_128_aes128,
    F_DERIVED | F_SP800_108_KDF | F_ENC_THEN_CKSUM | F_AEAD,
    _krb5_evp_encrypt_gcm,
    16,
    AES_GMAC_PRF
};

struct _krb5_encryption_type _krb5_enctype_aes256_gcm_128 = {
    ETYPE_AES256_GCM_128,
    "aes256-gcm-128",
    "aes256-gcm-128",
    16,
    1,
    12,
    &keytype_aes256_gcm,
    NULL, /* should never be called */
    &_krb5_checksum_gmac_128_aes256,
    F_DERIVED | F_SP800_108_KDF | F_ENC_THEN_CKSUM | F_AEAD,
    _krb5_evp_encrypt_gcm,
    16,
    AES_GMAC_PRF
};
