#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "elligator.h"

static const char *X25519_PRIME = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
static const unsigned long A = 486662;
static const unsigned long u = 2;

static inline int proper_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *bnctx) {
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *tmp3;

    tmp = BN_new();
    if (!tmp) {
        return 0;
    }
    tmp2 = BN_new();
    if (!tmp2) {
        goto free_tmp;
    }
    tmp3 = BN_new();
    if (!tmp2) {
        goto free_tmp2;
    }

    //tmp2 = (p-1)//4
    if (!BN_copy(tmp2, p)) {
        goto error;
    }
    if (!BN_sub_word(tmp2, 1)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    //tmp = u
    if (!BN_set_word(tmp, u)) {
        goto error;
    }
    //tmp = u**((p-1)//4), also know as sqrt(-1)
    if (!BN_mod_exp(tmp, tmp, tmp2, p, bnctx)) {
        goto error;
    }

    //tmp2 = (p+3)//8
    if (!BN_copy(tmp2, p)) {
        goto error;
    }
    if (!BN_add_word(tmp2, 3)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    //r = a**((p+3)//8), also known as mod_sqrt(a)
    if (!BN_mod_exp(tmp3, a, tmp2, p, bnctx)) {
        goto error;
    }

#if 0
    printf("Our sqrt input:\n%s\n",
            BN_bn2hex(a)
    );
#endif
#if 0
    printf("Our sqrt:\n%s\n",
            BN_bn2hex(tmp3)
    );
#endif

    //tmp2 = r**2, aka sqrt(a)**2
    if (!BN_mod_sqr(tmp2, tmp3, p, bnctx)) {
        goto error;
    }

#if 0
    printf("Squared result:\n%s\n",
            BN_bn2hex(tmp2)
    );
#endif

#if 0
    printf("Comparator:\n%s\n",
            BN_bn2hex(a)
    );
#endif

    if (BN_cmp(tmp2, a) != 0) {
        //r *= sqrt(-1)
        if (!BN_mod_mul(tmp3, tmp3, tmp, p, bnctx)) {
            goto error;
        }
    }

    //tmp = (p-1)//2
    if (!BN_copy(tmp, p)) {
        goto error;
    }
    if (!BN_sub_word(tmp, 1)) {
        goto error;
    }
    if (!BN_rshift1(tmp, tmp)) {
        goto error;
    }

    //True if tmp3 is negative (greater than (p-1)//2)
    if (BN_cmp(tmp3, tmp) == 1) {
        if (!BN_copy(tmp2, p)) {
            goto error;
        }
        if (!BN_sub_word(tmp2, 1)) {
            goto error;
        }
        //tmp2 = tmp3**((p-1)//2)
        if (!BN_mod_mul(tmp3, tmp3, tmp2, p, bnctx)) {
            goto error;
        }
    }


    if (!BN_copy(r, tmp3)) {
        goto error;
    }

#if 0
    if (!BN_nnmod(r, r, p, bnctx)) {
        goto error;
    }
#endif
    return 1;

error:
    BN_free(tmp3);
free_tmp2:
    BN_free(tmp2);
free_tmp:
    BN_free(tmp);
    return 0;
}

enum cobfs4_return_code elligator2(const EVP_PKEY * restrict pkey, uint8_t out_elligator[static restrict COBFS4_ELLIGATOR_LEN]) {
    BIGNUM *r;
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *p;
    BIGNUM *p_minus_one;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *neg_one;
    BN_CTX *bnctx;
    uint8_t skey[32];
    size_t skeylen = 32;
    EVP_PKEY_CTX *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        return -1;
    }

    x = BN_new();
    if (!x) {
        goto free_pkey_ctx;
    }

    y = BN_new();
    if (!y) {
        goto free_x;
    }

    p = BN_new();
    if (!p) {
        goto free_y;
    }

    r = BN_new();
    if (!r) {
        goto free_p;
    }

    neg_one = BN_new();
    if (!neg_one) {
        goto free_r;
    }

    p_minus_one = BN_new();
    if (!p_minus_one) {
        goto free_neg_one;
    }

    tmp = BN_new();
    if (!tmp) {
        goto free_p_minus_one;
    }

    tmp2 = BN_new();
    if (!tmp2) {
        goto free_tmp;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        goto free_tmp2;
    }

    if (!EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen)) {
        goto error;
    }

    /* p = (2**255)-19 */
    if (!BN_hex2bn(&p, X25519_PRIME)) {
        goto error;
    }

    if (!BN_copy(p_minus_one, p)) {
        goto error;
    }
    if (!BN_sub_word(p_minus_one, 1)) {
        goto error;
    }

#if 0
    BN_zero(neg_one);
    if (!BN_sub_word(neg_one, 1)) {
        goto error;
    }
#else
    if (!BN_copy(neg_one, p_minus_one)) {
        goto error;
    }
#endif

#if 0
    if (!BN_lebin2bn(skey, skeylen, x)) {
        goto error;
    }
#else
    if (!BN_bin2bn(skey, skeylen, x)) {
        goto error;
    }

    printf("Bit set? %d %d %d %d %d\n",
            BN_is_bit_set(x, 0),
            BN_is_bit_set(x, 1),
            BN_is_bit_set(x, 254),
            BN_is_bit_set(x, 255),
            BN_is_bit_set(x, 256)
            );
#endif
    if (!BN_mod(x, x, p, bnctx)) {
        goto error;
    }

    printf("Bit set? %d %d %d %d %d\n",
            BN_is_bit_set(x, 0),
            BN_is_bit_set(x, 1),
            BN_is_bit_set(x, 254),
            BN_is_bit_set(x, 255),
            BN_is_bit_set(x, 256)
            );

    /*
     * Do all the math here
     * x is the public key input
     * A is 486662
     * B is 1
     * p is (2**255)-19
     * u is 2
     * Preconditions:
     *  - x != -A
     *  - (-ux(x + A))**((p-1)/2) == 1
     *
     * Calculate y from curve equation:
     * y**2 = x**3 + Ax**2 + x
     *
     * Output is r
     * if y <= (p-1)/2
     *  - r = sqrt(-x/((x+A)u))
     * else
     *  - r = sqrt(-(x+A)/(ux))
    */

    if (!BN_set_word(tmp, A)) {
        goto error;
    }
#if 0
    if (!BN_mul(tmp, tmp, neg_one, bnctx)) {
        goto error;
    }
#else
    if (!BN_mod_mul(tmp, tmp, neg_one, p, bnctx)) {
        goto error;
    }
#endif

    /* Check if x == -A */
    if (BN_cmp(x, tmp) == 0) {
        /* Precondition failed */
        goto error;
    }

    /* tmp = -u*x*(x+A) */
    if (!BN_set_word(tmp, A)) {
        goto error;
    }
    if (!BN_mod_add(tmp, tmp, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(tmp, tmp, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(tmp, u)) {
        goto error;
    }
    if (!BN_mod_mul(tmp, tmp, neg_one, p, bnctx)) {
        goto error;
    }

    /* tmp2 = (p-1)/2 */
    if (!BN_copy(tmp2, p)) {
        goto error;
    }
    if (!BN_sub_word(tmp2, 1)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
#if 0
    if (!BN_nnmod(tmp2, tmp2, p, bnctx)) {
        goto error;
    }
#endif

    /* (-ux(x + A))**((p-1)/2) */
    if (!BN_mod_exp(tmp, tmp, tmp2, p, bnctx)) {
        goto error;
    }

    if (BN_cmp(tmp, p_minus_one) == 0) {
        if (!BN_copy(tmp, neg_one)) {
            goto error;
        }
    }

    if (!BN_is_one(tmp)) {
        /* Precondition failed */
        goto error;
    }

#if 1
    printf("(x):\n%s\n",
            BN_bn2hex(x)
    );
#endif

    /* y = y**2 = x**3 + Ax**2 + x */
    if (!BN_mod_sqr(tmp, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(tmp, tmp, x, p, bnctx)) {
        goto error;
    }
#if 1
    printf("(x**3):\n%s\n",
            BN_bn2hex(tmp)
    );
#endif
    if (!BN_mod_add(tmp, tmp, x, p, bnctx)) {
        goto error;
    }
#if 1
    printf("(x**3 + x):\n%s\n",
            BN_bn2hex(tmp)
    );
#endif
    if (!BN_mod_sqr(y, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(y, A)) {
        goto error;
    }
#if 1
    if (!BN_nnmod(y, y, p, bnctx)) {
        goto error;
    }
#endif
#if 1
    printf("(Ax**2):\n%s\n",
            BN_bn2hex(y)
    );
#endif
    if (!BN_mod_add(y, y, tmp, p, bnctx)) {
        goto error;
    }

#if 1
    printf("first (y**2):\n%s\n",
            BN_bn2hex(y)
    );
#endif

#if 0
    /* tmp2 = (p-1)/2 */
    if (!BN_copy(tmp2, p)) {
        goto error;
    }
    if (!BN_sub_word(tmp2, 1)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }
    if (!BN_mod_exp(tmp, y, tmp2, p, bnctx)) {
        goto error;
    }
#endif

#if 0
    if (!BN_is_one(tmp)) {
        /* y is not a square, this is an invalid point */
        printf("Why am I checking this?\n");
        goto error;
    }
#endif

#if 1
    printf("(y**2):\n%s\n",
            BN_bn2hex(y)
    );
#endif

#if 0
#if 1
    /* y = sqrt(y**2)*/
    if (!BN_mod_sqrt(y, y, p, bnctx)) {
        goto error;
    }
#else
    if (!BN_mod_sqr(y, y, p, bnctx)) {
        goto error;
    }
#endif
#else

    if (!BN_copy(tmp2, p_minus_one)) {
        goto error;
    }
    if (!BN_rshift1(tmp2, tmp2)) {
        goto error;
    }

#if 1
    printf("(p-1)/2:\n%s\n",
            BN_bn2hex(tmp2)
    );
#endif

#if 1
    printf("Y**2 comparison:\n%d\n",
            BN_cmp(y, tmp2)
    );
#endif

    if (!BN_copy(tmp, y)) {
        goto error;
    }

#if 0
    if (!BN_mod_exp(tmp, y, tmp2, p, bnctx)) {
        goto error;
    }
#if 1
    printf("Fancy y**2 chi experiment:\n%s\n",
            BN_bn2hex(tmp)
    );
#endif
#endif

    /* y = sqrt(y**2)*/
    if (!proper_sqrt(y, y, p, bnctx)) {
        goto error;
    }

#if 1
#if 0
    if (!BN_mod_mul(y, y, neg_one, p, bnctx)) {
        goto error;
    }
#endif

#if 1
    printf("Y/Chi power comparison:\n%d\n",
            BN_cmp(y, tmp2)
    );
#endif

#if 0
    if (!BN_mod_exp(tmp2, y, tmp2, p, bnctx)) {
        goto error;
    }
#if 1
    printf("Fancy y chi experiment:\n%s\n",
            BN_bn2hex(tmp2)
    );
#endif
#endif

#if 1
    //if (BN_cmp(tmp2, BN_value_one()) == 0) {
    if (BN_cmp(tmp, tmp2) == -1) {
    //if (BN_is_bit_set(x, 0)) {
        printf("We're negating y\n");
        if (!BN_mod_mul(y, y, neg_one, p, bnctx)) {
            goto error;
        }
    }
#endif

#if 0
    if (!BN_mod_mul(y, y, tmp2, p, bnctx)) {
        goto error;
    }
#else
#endif


#endif

#endif

#if 1
    printf("y:\n%s\n",
            BN_bn2hex(y)
    );
#endif

#if 0
    if (BN_is_zero(y)) {
        /* Precondition failed */
        goto error;
    }
#endif

    /* tmp = (p-1)/2 */
#if 0
    if (!BN_copy(tmp, p)) {
        goto error;
    }
    if (!BN_sub_word(tmp, 1)) {
        goto error;
    }
#else
    if (!BN_copy(tmp, p_minus_one)) {
        goto error;
    }
#endif
#if 1
    if (!BN_rshift1(tmp, tmp)) {
        goto error;
    }
#else
    if (!BN_set_word(tmp2, u)) {
        goto error;
    }
    if (!BN_mod_inverse(tmp2, tmp2, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(tmp, tmp, tmp2, p, bnctx)) {
        goto error;
    }
#endif

#if 1
    printf("Boundary:\n%s\n",
            BN_bn2hex(tmp)
    );
#endif

#if 1
    printf("Is it negative?:\n%d\n",
            BN_cmp(y, tmp)
    );
#endif

    /*
     * Output is r
     * if y <= (p-1)/2
     *  - r = sqrt(-x/((x+A)u))
     * else
     *  - r = sqrt(-(x+A)/(ux))
     */
#if 1
    if (BN_cmp(y, tmp) == 1) {
    //if (BN_cmp(tmp2, BN_value_one()) == 0) {
#else
    if (BN_cmp(y, tmp) == -1) {
#endif
        /* y is NOT element of sqrt(Fq) */
        if (!BN_copy(r, x)) {
            goto error;
        }
        if (!BN_add_word(r, A)) {
            goto error;
        }
#if 1
        printf("(x+A):\n%s\n",
                BN_bn2hex(r)
        );
#endif
        if (!BN_mod_mul(r, r, neg_one, p, bnctx)) {
            goto error;
        }

#if 1
        printf("-(x+A):\n%s\n",
                BN_bn2hex(r)
        );
#endif

        if (!BN_copy(tmp, x)) {
            goto error;
        }
        if (!BN_mul_word(tmp, u)) {
            goto error;
        }
#if 1
        printf("(ux):\n%s\n",
                BN_bn2hex(tmp)
        );
#endif
#if 0
        if (!BN_nnmod(tmp, tmp, p, bnctx)) {
            goto error;
        }
#endif


        if (!BN_mod_inverse(tmp, tmp, p, bnctx)) {
            goto error;
        }
#if 1
        printf("Inverse (ux):\n%s\n",
                BN_bn2hex(tmp)
        );
#endif
        if (!BN_mod_mul(r, r, tmp, p, bnctx)) {
            goto error;
        }
#if 1
        printf("(-(x+A)/(ux)):\n%s\n",
                BN_bn2hex(r)
        );
#endif

#if 1
#if 0
        if (!BN_mod_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#else
        if (!proper_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#endif
#else
        if (!BN_set_word(tmp, u)) {
            goto error;
        }
        if (!BN_copy(tmp2, p_minus_one)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_mod_exp(tmp, tmp, tmp2, p, bnctx)) {
            goto error;
        }
        printf("sqrt(-1):\n%s\n",
                BN_bn2hex(tmp)
        );

        if (!BN_copy(tmp2, p)) {
            goto error;
        }
        if (!BN_add_word(tmp2, 3)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_mod_exp(tmp2, r, tmp2, p, bnctx)) {
            goto error;
        }
        printf("diff sqrt:\n%s\n",
                BN_bn2hex(tmp2)
        );

        if (!BN_mod_mul(tmp2, tmp2, tmp, p, bnctx)) {
            goto error;
        }
        printf("Super duper result:\n%s\n",
                BN_bn2hex(tmp2)
              );

        if (!BN_mod_sqr(tmp2, tmp2, p, bnctx)) {
            goto error;
        }

        if (BN_cmp(tmp2, r) != 0) {
            printf("Holy fucking shit\n");

            if (!BN_mod_mul(tmp2, tmp2, tmp, p, bnctx)) {
                goto error;
            }
            printf("Super duper result:\n%s\n",
                    BN_bn2hex(tmp2)
            );
        }

#if 0
        if (!BN_mod_sqrt(tmp, r, p, bnctx)) {
            goto error;
        }

        if (!BN_mod_sqr(tmp, tmp, p, bnctx)) {
            goto error;
        }

        if (BN_cmp(tmp, r) != 0) {
            printf("Holy fucking shit\n");
        }
#endif

        if (!BN_mod_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#endif
#if 1
        printf("sqrt((-(x+A)/(ux))):\n%s\n",
                BN_bn2hex(r)
        );
#endif
    } else {
        /* y is element of sqrt(Fq) */
        if (!BN_copy(r, x)) {
            goto error;
        }
        if (!BN_add_word(r, A)) {
            goto error;
        }
#if 1
        printf("(x+A):\n%s\n",
                BN_bn2hex(r)
        );
#endif
        if (!BN_mul_word(r, u)) {
            goto error;
        }
#if 1
        printf("(x+A)u:\n%s\n",
                BN_bn2hex(r)
        );
#endif
#if 0
        if (!BN_nnmod(r, r, p, bnctx)) {
            goto error;
        }
#endif
        if (!BN_mod_mul(tmp, x, neg_one, p, bnctx)) {
            goto error;
        }
#if 1
        printf("-x:\n%s\n",
                BN_bn2hex(tmp)
        );
#endif

        if (!BN_mod_inverse(r, r, p, bnctx)) {
            goto error;
        }
#if 1
        printf("Inverse ((x+A)*u):\n%s\n",
                BN_bn2hex(tmp)
        );
#endif
        if (!BN_mod_mul(r, r, tmp, p, bnctx)) {
            goto error;
        }

#if 1
        printf("-x/((x+A)*u):\n%s\n",
                BN_bn2hex(r)
        );
#endif

#if 1
#if 0
        if (!BN_mod_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#else
        if (!proper_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#endif
#else
        if (!BN_set_word(tmp, u)) {
            goto error;
        }
        if (!BN_copy(tmp2, p_minus_one)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_rshift1(tmp2, tmp2)) {
            goto error;
        }
        if (!BN_mod_exp(tmp, tmp, tmp2, p, bnctx)) {
            goto error;
        }
        printf("sqrt(-1):\n%s\n",
                BN_bn2hex(tmp)
        );

        if (!BN_mod_sqrt(tmp, r, p, bnctx)) {
            goto error;
        }

        if (!BN_mod_sqr(tmp, tmp, p, bnctx)) {
            goto error;
        }

        if (BN_cmp(tmp, r) != 0) {
            printf("Holy fucking shit\n");
        }

        if (!BN_mod_sqrt(r, r, p, bnctx)) {
            goto error;
        }
#endif

#if 1
        printf("sqrt(-x/((x+A)*u)):\n%s\n",
                BN_bn2hex(r)
        );
#endif
    }

#if 0
    if (!BN_nnmod(r, r, p, bnctx)) {
        goto error;
    }
#endif

    memset(skey, 0, skeylen);
    if (!BN_bn2bin(r, skey + (skeylen - BN_num_bytes(r)))) {
        goto error;
    }

    BN_CTX_free(bnctx);
    BN_free(tmp2);
    BN_free(tmp);
    BN_free(p_minus_one);
    BN_free(neg_one);
    BN_free(r);
    BN_free(p);
    BN_free(y);
    BN_free(x);
    EVP_PKEY_CTX_free(pctx);

    memcpy(out_elligator, skey, 32);
    return COBFS4_OK;

error:
    BN_CTX_free(bnctx);
free_tmp2:
    BN_free(tmp2);
free_tmp:
    BN_free(tmp);
free_p_minus_one:
    BN_free(p_minus_one);
free_neg_one:
    BN_free(neg_one);
free_r:
    BN_free(r);
free_p:
    BN_free(p);
free_y:
    BN_free(y);
free_x:
    BN_free(x);
free_pkey_ctx:
    EVP_PKEY_CTX_free(pctx);
    return COBFS4_ERROR;
}

EVP_PKEY *elligator2_inv(const uint8_t buffer[static restrict COBFS4_ELLIGATOR_LEN]) {
    BIGNUM *r;
    BIGNUM *v;
    BIGNUM *e;
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *neg_one;
    BIGNUM *p_minus_one;
    BN_CTX *bnctx;
    uint8_t skey[32];
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;

    const unsigned long A = 486662;
    const unsigned long u = 2;
    const size_t skeylen = 32;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        return NULL;
    }

    v = BN_new();
    if (!v) {
        goto free_pkey_ctx;
    }

    e = BN_new();
    if (!e) {
        goto free_v;
    }

    x = BN_new();
    if (!x) {
        goto free_e;
    }

    y = BN_new();
    if (!y) {
        goto free_x;
    }

    p = BN_new();
    if (!p) {
        goto free_y;
    }

    r = BN_new();
    if (!r) {
        goto free_p;
    }

    neg_one = BN_new();
    if (!neg_one) {
        goto free_r;
    }

    p_minus_one = BN_new();
    if (!p_minus_one) {
        goto free_neg_one;
    }

    tmp = BN_new();
    if (!tmp) {
        goto free_p_minus_one;
    }

    tmp2 = BN_new();
    if (!tmp2) {
        goto free_tmp;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        goto free_tmp2;
    }

    /* p = (2**255)-19 */
    if (!BN_hex2bn(&p, X25519_PRIME)) {
        goto error;
    }

    BN_zero(neg_one);
    if (!BN_sub_word(neg_one, 1)) {
        goto error;
    }
    if (!BN_copy(p_minus_one, p)) {
        goto error;
    }
    if (!BN_sub_word(p_minus_one, 1)) {
        goto error;
    }
    if (!BN_bin2bn(buffer, 32, r)) {
        goto error;
    }

#if 1
    if (!BN_copy(tmp, p_minus_one)) {
        goto error;
    }
    if (!BN_rshift1(tmp, tmp)) {
        goto error;
    }
    if (BN_cmp(r, tmp) == 1) {
        printf("WE ARE NEGATING R IN THE INVERSE MAP\n");
        if (!BN_mod_mul(r, r, neg_one, p, bnctx)) {
            goto error;
        }
    }
#endif

    /*
     * Do all the math here
     * r is the raw buffer input
     * A is 486662
     * p is (2**255)-19
     * u is 2
     * Preconditions:
     *  - 1 + ur**2 != 0
     *  - (A**2)u(r**2) != (1 + ur**2)**2
     *
     * Output is x (y can also be calculated, but is not necessary)
     * v = -A/(1+ur**2)
     * e = (v**3+Av**2+v)**((p-1)/2)
     * x = ev-(1-e)A/2
     * y = -e*sqrt(x**3+Ax**2+x)
     */

    /* tmp = 1+ur**2 */
    if (!BN_mod_sqr(tmp, r, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(tmp, u)) {
        goto error;
    }
    if (!BN_add_word(tmp, 1)) {
        goto error;
    }

    if (BN_is_zero(tmp)) {
        /* Precondition failed */
        goto error;
    }

    /* tmp2 = (1+ur**2)**2 */
    if (!BN_mod_sqr(tmp2, tmp, p, bnctx)) {
        goto error;
    }

    /* tmp = (A**2)u(r**2) */
    if (!BN_mod_sqr(tmp, r, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(tmp, u)) {
        goto error;
    }
    if (!BN_mul_word(tmp, A)) {
        goto error;
    }
    if (!BN_mul_word(tmp, A)) {
        goto error;
    }
    if (!BN_nnmod(tmp, tmp, p, bnctx)) {
        goto error;
    }

    if (BN_cmp(tmp, tmp2) == 0) {
        /* Precondition failed */
        goto error;
    }

    /* v = -A/(1+ur**2) */
    if (!BN_set_word(tmp, A)) {
        goto error;
    }
    if (!BN_mod_mul(tmp, tmp, neg_one, p, bnctx)) {
        goto error;
    }
#if 0
    printf("Negative A:\n%s\n",
            BN_bn2hex(tmp)
    );
#endif
#if 1
    if (!BN_mod_sqr(v, r, p, bnctx)) {
        goto error;
    }
#else
    if (!BN_mod_mul(v, r, r, p, bnctx)) {
        goto error;
    }
#endif
#if 0
    printf("r:\n%s\n",
            BN_bn2hex(r)
    );
    printf("(r**2):\n%s\n",
            BN_bn2hex(v)
    );
#endif
    if (!BN_mul_word(v, u)) {
        goto error;
    }
    if (!BN_nnmod(v, v, p, bnctx)) {
        goto error;
    }
#if 0
    printf("(ur**2):\n%s\n",
            BN_bn2hex(v)
    );
#endif
    if (!BN_add_word(v, 1)) {
        goto error;
    }
#if 0
    printf("(1+ur**2):\n%s\n",
            BN_bn2hex(v)
    );
#endif

    if (!BN_mod_inverse(v, v, p, bnctx)) {
        goto error;
    }
#if 0
    printf("Inverse (1+ur**2):\n%s\n",
            BN_bn2hex(v)
    );
#endif
    if (!BN_mod_mul(v, tmp, v, p, bnctx)) {
        goto error;
    }

#if 0
    printf("Generating V:\n%s\n",
            BN_bn2hex(v)
    );
#endif

    /* e = (v**3+Av**2+v)**((p-1)/2) */
    if (!BN_mod_sqr(e, v, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(e, e, v, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_add(e, e, v, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_sqr(tmp, v, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(tmp, A)) {
        goto error;
    }
    if (!BN_mod_add(e, e, tmp, p, bnctx)) {
        goto error;
    }

    if (!BN_sub(tmp, p, BN_value_one())) {
        goto error;
    }
    if (!BN_rshift1(tmp, tmp)) {
        goto error;
    }
    if (!BN_mod_exp(e, e, tmp, p, bnctx)) {
        goto error;
    }

    if (BN_cmp(e, p_minus_one) == 0) {
        if (!BN_copy(e, neg_one)) {
            goto error;
        }
    }

    /* x = ev-(1-e)A/2 */
    if (!BN_set_word(tmp, 1)) {
        goto error;
    }
    if (!BN_sub(tmp, tmp, e)) {
        goto error;
    }
    if (!BN_mul_word(tmp, A)) {
        goto error;
    }
    if (!BN_rshift1(tmp, tmp)) {
        goto error;
    }
    if (!BN_mod_mul(x, e, v, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_sub(x, x, tmp, p, bnctx)) {
        goto error;
    }

    /* y = -e*sqrt(x**3+Ax**2+x) */
    if (!BN_mod_sqr(y, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(y, y, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_add(y, y, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_sqr(tmp, x, p, bnctx)) {
        goto error;
    }
    if (!BN_mul_word(tmp, A)) {
        goto error;
    }
    if (!BN_mod_add(y, y, tmp, p, bnctx)) {
        goto error;
    }
#if 0
    if (!BN_mod_sqrt(y, y, p, bnctx)) {
        goto error;
    }
#else
    if (!proper_sqrt(y, y, p, bnctx)) {
        goto error;
    }
#endif
    if (!BN_mod_mul(y, y, e, p, bnctx)) {
        goto error;
    }
    if (!BN_mod_mul(y, y, neg_one, p, bnctx)) {
        goto error;
    }

#if 0
    if (!BN_bn2lebinpad(x, skey, skeylen)) {
        goto error;
    }
#else
    if (!BN_bn2binpad(x, skey, skeylen)) {
        goto error;
    }
#endif

#if 1
    printf("Hash to curve:\nv:%s\ne:%s\nx:%s\ny:%s\n",
            BN_bn2hex(v),
            BN_bn2hex(e),
            BN_bn2hex(x),
            BN_bn2hex(y)
    );
#endif

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, skey, skeylen);
    if (!pkey) {
        goto error;
    }

    BN_CTX_free(bnctx);
    BN_free(tmp2);
    BN_free(tmp);
    BN_free(p_minus_one);
    BN_free(neg_one);
    BN_free(r);
    BN_free(p);
    BN_free(y);
    BN_free(x);
    BN_free(e);
    BN_free(v);
    EVP_PKEY_CTX_free(pctx);

    return pkey;

error:
    BN_CTX_free(bnctx);
free_tmp2:
    BN_free(tmp2);
free_tmp:
    BN_free(tmp);
free_p_minus_one:
    BN_free(p_minus_one);
free_neg_one:
    BN_free(neg_one);
free_r:
    BN_free(r);
free_p:
    BN_free(p);
free_y:
    BN_free(y);
free_x:
    BN_free(x);
free_e:
    BN_free(e);
free_v:
    BN_free(v);
free_pkey_ctx:
    EVP_PKEY_CTX_free(pctx);
    return NULL;
}

bool elligator_valid(const EVP_PKEY * restrict pkey) {
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    EVP_PKEY *res = NULL;

    if (elligator2(pkey, elligator) != COBFS4_OK) {
        return false;
    }

    res = elligator2_inv(elligator);
    if (res == NULL) {
        return false;
    }

    EVP_PKEY_free(res);
    return true;
}
