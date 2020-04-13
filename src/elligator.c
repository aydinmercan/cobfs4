#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "elligator.h"

static const char *X25519_PRIME = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
static const char *ROOT_NEG_ONE = "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0";
static const char *NEG_ROOT_NEG_ONE = "547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d";

BIGNUM *p;
BIGNUM *p_minus_one;
BIGNUM *neg_one;
BIGNUM *A;
BIGNUM *u;
BIGNUM *chi;
BIGNUM *root_neg_one;
BIGNUM *neg_root_neg_one;
BN_CTX *bnctx;

static inline void alloc_globals(void) {
    p = BN_new();
    p_minus_one = BN_new();
    neg_one = BN_new();
    A = BN_new();
    u = BN_new();
    chi = BN_new();
    root_neg_one = BN_new();
    neg_root_neg_one = BN_new();
    bnctx = BN_CTX_new();

    BN_set_word(A, 486662);
    BN_set_word(u, 2);

    BN_hex2bn(&p, X25519_PRIME);

    BN_copy(p_minus_one, p);
    BN_sub_word(p_minus_one, 1);

    BN_copy(neg_one, p_minus_one);

    BN_copy(chi, p_minus_one);
    BN_rshift1(chi, chi);

    BN_hex2bn(&root_neg_one, ROOT_NEG_ONE);
    BN_hex2bn(&neg_root_neg_one, NEG_ROOT_NEG_ONE);
}

static inline void free_globals(void) {
    BN_free(p);
    BN_free(p_minus_one);
    BN_free(neg_one);
    BN_free(u);
    BN_free(A);
    BN_free(chi);
    BN_free(root_neg_one);
    BN_free(neg_root_neg_one);
    BN_CTX_free(bnctx);
}

static inline bool is_square(const BIGNUM *a) {
    bool ret;
    BIGNUM *tmp = BN_new();
    BN_mod_exp(tmp, a, chi, p, bnctx);
    ret = (BN_is_one(tmp));
    BN_free(tmp);
    return ret;
}

static inline int proper_sqrt(BIGNUM *r, const BIGNUM *n) {
    if (!is_square(n)) {
        return 0;
    }

    BIGNUM *tmp = BN_new();
    BIGNUM *tmp2 = BN_new();

    //tmp = (p+3)//8
    BN_copy(tmp, p);
    BN_add_word(tmp, 3);
    BN_rshift(tmp, tmp, 3);

    //tmp = n**(p+3)//8
    BN_mod_exp(tmp, n, tmp, p, bnctx);

    //Square the square root
    BN_mod_sqr(tmp2, tmp, p, bnctx);

    if (BN_cmp(tmp2, n) != 0) {
        BN_mod_mul(tmp, tmp, root_neg_one, p, bnctx);
    }

    BN_copy(r, tmp);

    BN_free(tmp);
    BN_free(tmp2);

    return 1;
}

static inline int inv_sqrt(BIGNUM *r, const BIGNUM *n) {
    if (!is_square(n)) {
        return 0;
    }

    BIGNUM *tmp = BN_new();
    BIGNUM *tmp2 = BN_new();

    //tmp = (p-5)//8
    BN_copy(tmp, p);
    BN_sub_word(tmp, 5);
    BN_rshift(tmp, tmp, 3);

    //tmp = n**(p-5)//8
    BN_mod_exp(tmp, n, tmp, p, bnctx);

    //Square the square root
    BN_mod_sqr(tmp2, tmp, p, bnctx);

    //tmp2 = x*invsqrt**2
    BN_mod_mul(tmp2, tmp2, n, p, bnctx);

    //If tmp2 == -1 or -sqrt(-1), negate the calculated square root
    if ((BN_cmp(tmp2, neg_one) == 0)
            || (BN_cmp(tmp2, neg_root_neg_one) == 0)) {
        BN_mod_mul(tmp, tmp, root_neg_one, p, bnctx);
    }

    BN_copy(r, tmp);

    BN_free(tmp);
    BN_free(tmp2);

    return 1;
}

static inline bool forward_map_valid(const BIGNUM *n) {
    bool ret;
    BIGNUM *tmp = BN_new();

    //tmp = n(n+A)
    BN_copy(tmp, n);
    BN_add(tmp, tmp, A);
    BN_mod_mul(tmp, tmp, n, p, bnctx);

    ret = is_square(tmp);

    BN_free(tmp);

    return ret;
}

static inline bool is_positive(const BIGNUM *n) {
    return (BN_cmp(n, chi) != 1);
}

static inline bool is_negative(const BIGNUM *n) {
    return !is_positive(n);
}

enum cobfs4_return_code elligator2_inv(const EVP_PKEY * restrict pkey,
        uint8_t out_elligator[static restrict COBFS4_ELLIGATOR_LEN]) {
    BIGNUM *r;
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BN_CTX *bnctx;
    uint8_t skey[32];
    size_t skeylen = 32;
    EVP_PKEY_CTX *pctx;

    alloc_globals();

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    x = BN_new();
    y = BN_new();
    r = BN_new();
    tmp = BN_new();
    tmp2 = BN_new();
    bnctx = BN_CTX_new();

    EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen);

    BN_bin2bn(skey, skeylen, x);

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

    BN_bn2binpad(r, skey, skeylen);

    BN_CTX_free(bnctx);
    BN_free(tmp2);
    BN_free(tmp);
    BN_free(r);
    BN_free(y);
    BN_free(x);
    EVP_PKEY_CTX_free(pctx);

    memcpy(out_elligator, skey, 32);

    free_globals();

    return COBFS4_OK;
}

EVP_PKEY *elligator2(const uint8_t buffer[static restrict COBFS4_ELLIGATOR_LEN]) {
    BIGNUM *r;
    BIGNUM *v;
    BIGNUM *e;
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BN_CTX *bnctx;
    uint8_t skey[32];
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;

    const size_t skeylen = 32;

    alloc_globals();

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    v = BN_new();
    e = BN_new();
    x = BN_new();
    y = BN_new();
    r = BN_new();
    tmp = BN_new();
    tmp2 = BN_new();
    bnctx = BN_CTX_new();

    BN_bin2bn(buffer, 32, r);

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

    BN_bn2binpad(x, skey, skeylen);

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, skey, skeylen);

    BN_CTX_free(bnctx);
    BN_free(tmp2);
    BN_free(tmp);
    BN_free(r);
    BN_free(y);
    BN_free(x);
    BN_free(e);
    BN_free(v);
    EVP_PKEY_CTX_free(pctx);

    free_globals();

    return pkey;
}

bool elligator_valid(const EVP_PKEY * restrict pkey) {
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    EVP_PKEY *res = NULL;

    if (elligator2_inv(pkey, elligator) != COBFS4_OK) {
        return false;
    }

    res = elligator2(elligator);
    if (res == NULL) {
        return false;
    }

    EVP_PKEY_free(res);
    return true;
}
