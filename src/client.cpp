#include "headers.h"


// Функція для обчислення значення r
BIGNUM* computeR(const BIGNUM* g, const BIGNUM* k, const BIGNUM* p) {
    BIGNUM* r = BN_new();
    BN_mod_exp(r, g, k, p, BN_CTX_new());  // Обчислюємо r = g^k mod p
    return r;
}

// Функція для обчислення значення s
BIGNUM* computeS(const BIGNUM* k, const BIGNUM* x, const BIGNUM* r, const BIGNUM* p) {
    BIGNUM* s = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    BIGNUM* p_minus_1 = BN_new();
    BN_sub(p_minus_1, p, BN_value_one());  // p_minus_1 = p - 1

    BN_mod_mul(temp1, x, r, p_minus_1, BN_CTX_new());  // temp1 = x * r mod (p-1)
    BN_mod_sub(temp2, k, temp1, p_minus_1, BN_CTX_new());  // temp2 = k - temp1 mod (p-1)
    BN_mod(s, temp2, p_minus_1, BN_CTX_new());  // Обчислюємо s = temp2 mod (p-1)

    BN_free(temp1);
    BN_free(temp2);
    BN_free(p_minus_1);
    return s;
}

