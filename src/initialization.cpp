#include "headers.h"
#include "headers.h"


// ������� ��� ��������� ���������� �������� ����� p
BIGNUM* generatePrime(int bits) {
    BIGNUM* p = BN_new();
    BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL);
    return p;
}

// ������� ��� ����������� ���������� �����
BIGNUM* findGenerator(const BIGNUM* p) {
    BIGNUM* g = BN_new();
    BIGNUM* temp = BN_new();
    BN_set_word(temp, 2);  // ������������� 2 �� ��������� �������� g
    BN_mod_exp(g, temp, p, p, BN_CTX_new());  // ���������� g = 2^p mod p
    BN_free(temp);
    return g;
}

// ������� ��� ��������� ����������� ���������� �������� x
BIGNUM* generateSecret(const BIGNUM* p) {
    BIGNUM* x = BN_new();
    BN_rand_range(x, p);  // �������� ��������� ����� x � �������� [1, p-1]
    return x;
}

// ������� ��� ���������� ��������� ����� y
BIGNUM* computePublicKey(const BIGNUM* x, const BIGNUM* g, const BIGNUM* p) {
    BIGNUM* y = BN_new();
    BN_mod_exp(y, g, x, p, BN_CTX_new());  // ���������� y = g^x mod p
    return y;
}
