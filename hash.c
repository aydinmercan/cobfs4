#include <openssl/evp.h>

#include <string.h>

#include "hash.h"

int hash_data(unsigned char *mesg, size_t mesg_len, unsigned char out_buf[static 32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    unsigned char digest[32];

    if (!ctx) {
        return -1;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha512_256(), NULL)) {
        goto error;
    }

    if (!EVP_DigestUpdate(ctx, mesg, mesg_len)) {
        goto error;
    }

    if (!EVP_DigestFinal_ex(ctx, digest, NULL)) {
        goto error;
    }

    memcpy(out_buf, digest, 32);

    EVP_MD_CTX_free(ctx);
    return 0;

error:
    EVP_MD_CTX_free(ctx);
    return -1;
}