#include "headers.h"


BIGNUM* generateRandomValue(const BIGNUM* p) {
    BIGNUM* k = BN_new();
    BN_rand_range(k, p);  // Генеруємо випадкове число k з діапазону [1, p-1]
    return k;
}

// Функція для перевірки отриманої відповіді
bool verifyResponse(const BIGNUM* r, const BIGNUM* s, const BIGNUM* y, const BIGNUM* g, const BIGNUM* p) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* u1 = BN_new();
    BIGNUM* u2 = BN_new();
    BIGNUM* v = BN_new();

    BN_mod_exp(u1, y, r, p, ctx);  // u1 = y^r mod p
    char* u1_1 = BN_bn2dec(u1);
    cout << " u1 = y^r mod p : " << u1<<endl;
    BN_mod_exp(u2, g, s, p, ctx);  // u2 = g^s mod p
    char* u2_2 = BN_bn2dec(u2);
    cout << " u2 = g^s mod p : " << u2 << endl;
    BN_mod_mul(v, u1, u2, p, ctx);  // v = u1 * u2 mod p
    char* v_1 = BN_bn2dec(v);
    cout << " v = u1 * u2 mod p : " << v << endl;
    BN_mod(v, v, p, ctx);  // v = v mod p
    char* v_2 = BN_bn2dec(v);
    cout << " v = v mod p : " << v_2 << endl;

    char* cmp = BN_bn2dec(v);
    char* r_1 = BN_bn2dec(r);
    cout << cmp << " == " << r_1 << " ??? " << endl;
    bool isVerified = (BN_cmp(v, r) == 0);  // Перевіряємо, чи v = r

    BN_free(u1);
    BN_free(u2);
    BN_free(v);
    BN_CTX_free(ctx);
    OPENSSL_free(u1_1);
    OPENSSL_free(u2_2);
    OPENSSL_free(v_1);
    OPENSSL_free(v_2);
    OPENSSL_free(cmp);
    OPENSSL_free(r_1);
    return isVerified;
}

