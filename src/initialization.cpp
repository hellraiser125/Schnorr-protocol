#include "headers.h"
#include "headers.h"


// Функція для генерації безпечного простого числа p
BIGNUM* generatePrime(int bits) {
    BIGNUM* p = BN_new();
    BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL);
    return p;
}

// Функція для знаходження генератора групи
BIGNUM* findGenerator(const BIGNUM* p) {
    BIGNUM* g = BN_new();
    BIGNUM* temp = BN_new();
    BN_set_word(temp, 2);  // Використовуємо 2 як початкове значення g
    BN_mod_exp(g, temp, p, p, BN_CTX_new());  // Обчислюємо g = 2^p mod p
    BN_free(temp);
    return g;
}

// Функція для генерації випадкового секретного значення x
BIGNUM* generateSecret(const BIGNUM* p) {
    BIGNUM* x = BN_new();
    BN_rand_range(x, p);  // Генеруємо випадкове число x з діапазону [1, p-1]
    return x;
}

// Функція для обчислення публічного ключа y
BIGNUM* computePublicKey(const BIGNUM* x, const BIGNUM* g, const BIGNUM* p) {
    BIGNUM* y = BN_new();
    BN_mod_exp(y, g, x, p, BN_CTX_new());  // Обчислюємо y = g^x mod p
    return y;
}
