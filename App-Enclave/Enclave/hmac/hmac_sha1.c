/**
* @file hmac_sha1.c  Implements HMAC-SHA1 as of RFC 2202
*
* Copyright (C) 2010 Creytiv.com
*/
#include <string.h>
#include <stdint.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#else

#include <sha/sha.h>

#endif

#include <hmac/hmac.h>


/** SHA-1 Block size */
#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE   (64)
#endif


/**
* Function to compute the digest
*
* @param k   Secret key
* @param lk  Length of the key in bytes
* @param d   Data
* @param ld  Length of data in bytes
* @param out Digest output
* @param t   Size of digest output
*/
void hmac_sha1(const uint8_t *k,  /* secret key */
        size_t lk,       /* length of the key in bytes */
        const uint8_t *d,  /* data */
        size_t ld,       /* length of data in bytes */
        uint8_t *out,      /* output buffer, at least "t" bytes */
        size_t *t) {
#ifdef USE_OPENSSL

	if (!HMAC(EVP_sha1(), k, (int)lk, d, ld, out, t)) {
		ERR_clear_error();
	}
#else
    SHA_CTX ictx, octx;
    uint8_t isha[SHA_DIGEST_LENGTH], osha[SHA_DIGEST_LENGTH];
    uint8_t key[SHA_DIGEST_LENGTH];
    uint8_t buf[SHA_BLOCKSIZE];
    size_t i;

    if (lk > SHA_BLOCKSIZE) {
        SHA_CTX tctx;

        MY_SHA1_Init(&tctx);
        MY_SHA1_Update(&tctx, k, lk);
        MY_SHA1_Final(key, &tctx);

        k = key;
        lk = SHA_DIGEST_LENGTH;
    }

    /**** Inner Digest ****/

    MY_SHA1_Init(&ictx);

    /* Pad the key for inner digest */
    for (i = 0; i < lk; ++i) {
        buf[i] = k[i] ^ 0x36;
    }
    for (i = lk; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x36;
    }

    MY_SHA1_Update(&ictx, buf, SHA_BLOCKSIZE);
    MY_SHA1_Update(&ictx, d, ld);

    MY_SHA1_Final(isha, &ictx);

    /**** Outer Digest ****/

    MY_SHA1_Init(&octx);

    /* Pad the key for outter digest */

    for (i = 0; i < lk; ++i) {
        buf[i] = k[i] ^ 0x5c;
    }
    for (i = lk; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x5c;
    }

    MY_SHA1_Update(&octx, buf, SHA_BLOCKSIZE);
    MY_SHA1_Update(&octx, isha, SHA_DIGEST_LENGTH);

    MY_SHA1_Final(osha, &octx);

    /* truncate and print the results */
    *t = *t > SHA_DIGEST_LENGTH ? SHA_DIGEST_LENGTH : *t;
    memcpy(out, osha, *t);
#endif
}
