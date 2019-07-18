#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "cobfs4.h"
#include "elligator.h"

void test_elligator(void) {
    EVP_PKEY *pkey;
    EVP_PKEY *peerkey;
    size_t skeylen;
    unsigned char *skey;
    unsigned char *skey2;
    unsigned char *skey3;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *x;
    BN_CTX *bnctx;
    size_t i;

    p = BN_new();
    tmp = BN_new();
    x = BN_new();
    bnctx = BN_CTX_new();

    pkey = EVP_PKEY_new();

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);

    EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);

    skey = OPENSSL_malloc(skeylen);
    skey2 = OPENSSL_malloc(skeylen);

    if (!EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen)) {
        printf("Get raw call failed\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    skey3 = elligator2(pkey);

    if (skey3) {
        peerkey = elligator2_inv(skey3);
        if (peerkey) {
            if (!EVP_PKEY_get_raw_public_key(peerkey, skey2, &skeylen)) {
                printf("Get raw call failed\n");
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            }
            for (i = 0; i < 32; ++i) {
                printf("%02x", skey[i]);
            }
            printf("\n");
            for (i = 0; i < 32; ++i) {
                printf("%02x", skey2[i]);
            }
            printf("\n");
            if (memcmp(skey, skey2, 32) == 0) {
                printf("Elligator works as intended\n");
            } else {
                printf("Elligator FAILED\n");
            }
            EVP_PKEY_free(peerkey);
        }
    } else {
        printf("Generated key was not valid for elligator2\n");
    }

    OPENSSL_free(skey);
    OPENSSL_free(skey2);
    OPENSSL_free(skey3);

    BN_free(p);
    BN_free(tmp);
    BN_free(x);

    BN_CTX_free(bnctx);

    EVP_PKEY_free(pkey);

    EVP_PKEY_CTX_free(pctx);
}
