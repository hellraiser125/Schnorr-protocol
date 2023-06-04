#include "headers.h"

int main() {

    // Встановлення довжини p
    int bits = 1024;
    // Генерація безпечного простого числа p
    BIGNUM* p = generatePrime(bits);
    int sizeInBits = BN_num_bits(p);
    std::cout << "Size of BIGNUM in bits: " << sizeInBits << std::endl;
    // Знаходження генератора групи
    BIGNUM* g = findGenerator(p);
    // Генерація випадкового секретного значення x
    BIGNUM* x = generateSecret(p);
    // Обчислення публічного ключа y
    BIGNUM* y = computePublicKey(x, g, p);
    // Генерація випадкового викликаного значення k
    BIGNUM* k = generateRandomValue(p);
    // Обчислення значення r
    BIGNUM* r = computeR(g, k, p);
    // Обчислення значення s
    BIGNUM* s = computeS(k, x, r, p);

    // Виведення результатів
    char* p_str = BN_bn2dec(p);
    char* g_str = BN_bn2dec(g);
    char* x_str = BN_bn2dec(x);
    char* y_str = BN_bn2dec(y);
    char* k_str = BN_bn2dec(k);
    char* r_str = BN_bn2dec(r);
    char* s_str = BN_bn2dec(s);
    std::cout << "Prime modulus p: " << p_str << std::endl<<endl;
    std::cout << "Generator g: " << g_str << std::endl<<endl;
    std::cout << "Secret value x: " << x_str << std::endl<<endl;
    std::cout << "Public key y: " << y_str << std::endl<<endl;
    cout << "Alice sending y to Bob...." << endl << endl;
    std::cout << "Bob generating random value k: " << k_str << std::endl<<endl;
    cout << "Bob sending key to Alice..." << endl << endl;
    std::cout << "Alice calculate value r = g^k (mod p): " << r_str << std::endl<<endl;
    std::cout << "Alice calculate value ss = (k - x * r): " << s_str << std::endl<<endl;
    cout << "Alcie sending (r,s) to Bob and waiting for response..." << endl << endl;
    cout << "Bob cheking Alice values and calculate his own fo gerring response....." << endl << endl;

    y = generatePrime(160);
    char* y_1 = BN_bn2dec(y);
    cout << "Changed value y before review..." << y_1 << endl << endl;
    // Перевірка отриманої відповіді
    bool isVerified = verifyResponse(r, s, y, g, p);
    if (isVerified) {
        std::cout << "Response is verified." << std::endl;
    }
    else {
        std::cout << "Response is NOT verified." << std::endl;
    }

    // Очищення пам'яті
    BN_free(p);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    BN_free(k);
    BN_free(r);
    BN_free(s);
    OPENSSL_free(r_str);
    OPENSSL_free(p_str);
    OPENSSL_free(g_str);
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);
    OPENSSL_free(k_str);
    OPENSSL_free(s_str);
    return 0;
}