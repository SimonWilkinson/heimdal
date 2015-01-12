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

static inline int
_krb5_iov_nextcrypt(struct krb5_crypto_iov *iov, int niov,
		    int *curridx)
{
    int i;

    for (i = *curridx + 1; i < niov; i++) {
	if (iov[i].flags == KRB5_CRYPTO_TYPE_DATA
	    || iov[i].flags == KRB5_CRYPTO_TYPE_HEADER
	    || iov[i].flags == KRB5_CRYPTO_TYPE_PADDING) {
	    *curridx = i;
	    return 0;
	}
    }
    return -1;
}

/*
 * If we have a group of iovecs which have been split up from
 * a single common buffer, expand the 'current' iovec out to
 * be as large as possible.
 */

static inline void
_krb5_iov_expand(struct krb5_crypto_iov *iov, int niov,
		 krb5_data *current, int *curidx)
{
   int nextidx = *curidx + 1;

   if (nextidx == niov)
       return;

   while (iov[nextidx].flags == KRB5_CRYPTO_TYPE_DATA
	  || iov[nextidx].flags == KRB5_CRYPTO_TYPE_HEADER
	  || iov[nextidx].flags == KRB5_CRYPTO_TYPE_PADDING) {
	if ((char *)current->data + current->length != iov[nextidx].data.data)
            return;
	current->length += iov[nextidx].data.length;
	*curidx = nextidx;
	nextidx++;
    }

    return;
}

/* encryptp */
/* Pass iovecs into EVP_EncryptUpdate until we have added all of the whole
 * blocks (less than 1 block size remains)
 * Call EVP_EncryptFinal_ex() which had better not write any more data.
 */

/* To do a straightforward EVP encryption with iovecs is tricky */

static inline int
_krb5_iov_fillbuf(unsigned char *buf, size_t length, krb5_data *current,
		  int curridx, struct krb5_crypto_iov *iov, int niov,
		  krb5_data *next, int *nextidx)
{
    while (current->length <= length) {
	memcpy(buf, current->data, current->length);
	buf += current->length;
	length -= current->length;

	if (_krb5_iov_nextcrypt(iov, niov, &curridx) != 0)
	    return EINVAL;

	current = &iov[curridx].data;
    }

    if (length > 0) {
	memcpy(buf, current->data, length);
	if (next != NULL) {
	    next->data = (char *)current->data + length;
	    next->length = current->length - length;
	    *nextidx = curridx;
	}
    } else if (next != NULL) {
	*next = *current;
	*nextidx = curridx;
    }

    return 0;
}

static inline int
_krb5_iov_fillvec(unsigned char *buf, size_t length, krb5_data *current,
		  int curridx, struct krb5_crypto_iov *iov, int niov,
		  krb5_data *next, int *nextidx)
{
    while (current->length <= length) {
	memcpy(current->data, buf, current->length);
	buf += current->length;
	length -= current->length;

	if (_krb5_iov_nextcrypt(iov, niov, &curridx) != 0)
	    return EINVAL;

	current = &iov[curridx].data;
    }

    if (length > 0) {
	memcpy(current->data, buf, length);
	if (next != NULL) {
	    next->data = (char *)current->data + length;
	    next->length = current->length - length;
	    *nextidx = curridx;
	}
    } else if (next != NULL) {
	*next = *current;
	*nextidx = curridx;
    }

    return 0;
}

int
_krb5_evp_encrypt_iov(krb5_context context,
		      struct _krb5_key_data *key,
		      struct krb5_crypto_iov *iov,
		      int niov,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    size_t blocksize, blockmask, wholeblocks;
    krb5_data current;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    int curridx, ret;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);

    blockmask = ~(blocksize - 1);

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    curridx = -1;
    if (_krb5_iov_nextcrypt(iov, niov, &curridx) != 0)
	return EINVAL;
    current = iov[curridx].data;

    while (curridx < niov) {
	_krb5_iov_expand(iov, niov, &current, &curridx);

	/* Number of bytes of data in this iovec that are in whole blocks */
        wholeblocks = current.length & ~blockmask;

        if (wholeblocks != 0) {
            EVP_Cipher(c, current.data, current.data, wholeblocks);
            current.data = (char *)current.data + wholeblocks;
            current.length -= wholeblocks;
        }

        /* If there's a partial block of data remaining in the current iovec, steal
         * enough from subsequent iovecs to form a whole block */
        if (current.length > 0) {
	    /* Build up a block's worth of data in tmp, leaving current pointing at where
	     * we started */
            ret = _krb5_iov_fillbuf(tmp, blocksize, &current, curridx,
				    iov, niov, NULL, NULL);
            if (ret)
		return ret;

            EVP_Cipher(c, tmp, tmp, blocksize);

            /* Copy the data in tmp back into the iovecs that it came from, advance
             * current and curridx to point at the next data to process */
            ret = _krb5_iov_fillvec(tmp, blocksize, &current, curridx, iov, niov,
				    &current, &curridx);
            if (ret)
		return ret;

        } else {
            if (_krb5_iov_nextcrypt(iov, niov, &curridx) != 0)
		return 0; /* All done */

            current = iov[curridx].data;
        }
    }
    return 0;
}

static size_t
_krb5_iov_cryptlength(struct krb5_crypto_iov *iov, int niov)
{
    int curridx;
    size_t length = 0;

    curridx = -1;
    while (_krb5_iov_nextcrypt(iov, niov, &curridx) == 0)
	length += iov[curridx].data.length;

    return length;
}

int
_krb5_evp_encrypt_iov_cts(krb5_context context,
			  struct _krb5_key_data *key,
			  struct krb5_crypto_iov *iov,
			  int niov,
			  krb5_boolean encryptp,
			  int usage,
			  void *ivec)
{
    size_t blocksize, blockmask, wholeblocks, length;
    size_t remaining;
    size_t partiallen;
    krb5_data current, lastblock, partialblock;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH], tmp2[EVP_MAX_BLOCK_LENGTH];
    unsigned char tmp3[EVP_MAX_BLOCK_LENGTH], ivec2[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    int i, curridx, lastidx, partialidx;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);
    blockmask = ~(blocksize - 1);

    length = _krb5_iov_cryptlength(iov, niov);

    if (length < blocksize) {
	krb5_set_error_message(context, EINVAL,
			       "message block too short");
	return EINVAL;
    }

    if (length == blocksize)
	return _krb5_evp_encrypt_iov(context, key, iov, niov, encryptp, usage, ivec);

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    if (encryptp) {
	/* On our first pass, we want to process everything but the
	 * final partial block */
	remaining = ((length - 1) & blockmask);
	partiallen = length - remaining;
    } else {
	/* Decryption needs to leave 2 whole blocks and a partial for
	 * further processing */
	if (length > 2 * blocksize) {
	    remaining = (((length - 1) / blocksize) * blocksize) - (blocksize*2);
	    partiallen = length - remaining - (blocksize * 2);
	} else {
	    remaining = 0;
	    partiallen = length - blocksize;
	}
    }

    curridx = -1;
    _krb5_iov_nextcrypt(iov, niov, &curridx);
    current = iov[curridx].data;

    while (remaining > 0) {
	_krb5_iov_expand(iov, niov, &current, &curridx);

	/* If the iovec has more data than we need, just use it */
	if (current.length >= remaining) {
	    EVP_Cipher(c, current.data, current.data, remaining);

	    /* We've just encrypted the last block of data. Make a copy
	     * of it (and its location) for the CTS dance, below */
	    lastblock.data = (char *)current.data + remaining - blocksize;
	    lastblock.length = blocksize;
	    lastidx = curridx;
	    memcpy(ivec2, lastblock.data, blocksize);

	    current.data = (char *)current.data + remaining;
	    current.length -= remaining;
	    remaining = 0;
	} else {
	    /* Otherwise, use as much as we can, firstly all of the whole blocks */
	    wholeblocks = current.length & blockmask;

	    if (wholeblocks > 0) {
		EVP_Cipher(c, current.data, current.data, wholeblocks);
		current.data = (char *)current.data + wholeblocks;
		current.length -= wholeblocks;
		remaining -= wholeblocks;
	    }

	    /* Then, if we have partial data left, steal enough from subsequent
	     * iovecs to make a whole block */
	    if (current.length != wholeblocks) {

		if (!encryptp || remaining != blocksize) {
		    _krb5_iov_fillbuf(tmp, blocksize, &current, curridx,
				      iov, niov, NULL, NULL);

		    EVP_Cipher(c, tmp, tmp, blocksize);
		     _krb5_iov_fillvec(tmp, blocksize, &current, curridx,
				       iov, niov, &current, &curridx);
		} else {
		    /* If we're encrypting, we want to keep the last block
		     * handy */
		    lastblock = current;
		    lastidx = curridx;
		    _krb5_iov_fillbuf(ivec2, blocksize, &current, curridx,
				      iov, niov, &current, &curridx);
		    EVP_Cipher(c, ivec2, ivec2, blocksize);
		}
		remaining -= blocksize;
            }
        }

        if (current.length == 0) {
            /* Processed all of the current iovec, get the next one */
            _krb5_iov_nextcrypt(iov, niov, &curridx);
            current = iov[curridx].data;
        }
    }

    /* Encryption */
    if (encryptp) {
	/* Copy the partial block into tmp */
	partialblock = current;
	partialidx = curridx;
	_krb5_iov_fillbuf(tmp, partiallen, &partialblock, partialidx, iov, niov,
			  NULL, NULL);

	/* XOR the final partial block with ivec2 */
	for (i = 0; i < partiallen; i++)
	    tmp[i] = tmp[i] ^ ivec2[i]; /* XORing final partial block with ivec2 */
	for (; i < blocksize; i++)
	    tmp[i] = 0 ^ ivec2[i]; /* XORing 0s when final partial block is exhausted */

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

	if (lastblock.length >= blocksize) {
	    EVP_Cipher(c, lastblock.data, tmp, blocksize);
	} else {
	    EVP_Cipher(c, tmp, tmp, blocksize);
	    _krb5_iov_fillvec(tmp, blocksize, &lastblock, lastidx,
			      iov, niov, NULL, NULL);
	}

	_krb5_iov_fillvec(ivec2, partiallen, &partialblock, partialidx,
			  iov, niov, NULL, NULL);

        if (ivec)
	    memcpy(ivec, lastblock.data, blocksize);

        return 0;
    }

    /* Decryption */

    /* Make a copy of the 2nd last full ciphertext block in ivec2 before decrypting it.
     * If no such block exists, use ivec or zero_ivec for ivec2 */
    if (length < blocksize * 2) {
	if (ivec)
	   memcpy(ivec2, ivec, blocksize);
	else
	   memcpy(ivec2, zero_ivec, blocksize);
    } else {
        if (current.length >= blocksize) {
	    memcpy(ivec2, current.data, blocksize);
            EVP_Cipher(c, current.data, current.data, current.length);
            current.data = (char *)current.data + blocksize;
            current.length -= blocksize;
            if (current.length == 0) {
                /* Processed all of the current iovec, get the next one */
                _krb5_iov_nextcrypt(iov, niov, &curridx);
                current = iov[curridx].data;
            }
        } else {
	    _krb5_iov_fillbuf(ivec2, blocksize, &current, curridx, iov, niov,
			      NULL, NULL);
	    EVP_Cipher(c, tmp, ivec2, blocksize);
	    _krb5_iov_fillvec(tmp, blocksize, &current, curridx, iov, niov,
			      &current, &curridx);
	}
    }

    lastblock = current;
    lastidx = curridx;
    _krb5_iov_fillbuf(tmp, blocksize, &lastblock, lastidx, iov, niov, &current, &curridx);
    EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
    EVP_Cipher(c, tmp2, tmp, blocksize); /* tmp eventually becomes output ivec */

    partialblock = current;
    partialidx = curridx;
    _krb5_iov_fillbuf(tmp3, partiallen, &partialblock, partialidx, iov, niov, NULL, NULL);
    memcpy(tmp3 + partiallen, tmp2 + partiallen, blocksize - partiallen); /* xor 0 */
    for (i = 0; i < partiallen; i++)
	tmp2[i] = tmp2[i] ^ tmp3[i];

    _krb5_iov_fillvec(tmp2, partiallen, &partialblock, partialidx, iov, niov, NULL, NULL);

    EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
    EVP_Cipher(c, tmp3, tmp3, blocksize);

    for (i = 0; i < blocksize; i++)
	tmp3[i] ^= ivec2[i];

    _krb5_iov_fillvec(tmp3, blocksize, &lastblock, lastidx, iov, niov, NULL, NULL);

    if (ivec)
	memcpy(ivec, tmp, blocksize);

    return 0;
}

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
