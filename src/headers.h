#include "lib.h"

BIGNUM* generatePrime(int bits);
BIGNUM* findGenerator(const BIGNUM* p);
BIGNUM* generateSecret(const BIGNUM* p);
BIGNUM* computePublicKey(const BIGNUM* x, const BIGNUM* g, const BIGNUM* p);
BIGNUM* generateRandomValue(const BIGNUM* p);
BIGNUM* computeR(const BIGNUM* g, const BIGNUM* k, const BIGNUM* p);
BIGNUM* computeS(const BIGNUM* k, const BIGNUM* x, const BIGNUM* r, const BIGNUM* p);
bool verifyResponse(const BIGNUM* r, const BIGNUM* s, const BIGNUM* y,const BIGNUM* g, const BIGNUM* p);
