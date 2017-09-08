#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "bitcoin.h"

static const uint32_t sha256_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x)  & (z)) ^ ((y) & (z)))
#define SIGMA0(x)   (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x)   (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define EPSILON0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define EPSILON1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

void sha256_process(const uint8_t block[64], uint64_t H[8])
{
    uint32_t W[64];

    int i, j;
    for (i = 0, j = 0; i < 16; i++, j += 4) {
        W[i] = (block[j] << 24) | (block[j + 1] << 16) |
            (block[j + 2] << 8) | block[j + 3];
    }

    for (; i < 64; i++) {
        W[i] = EPSILON1(W[i - 2]) + W[i - 7] +
            EPSILON0(W[i - 15]) + W[i - 16];
    }

    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) +
            sha256_constants[i] + W[i];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

void sha256_encode(uint8_t *msg, uint64_t len, uint8_t digest[SHA256_SIZE])
{
    uint64_t H[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    uint64_t bitlen = len * 8;

    for (;;) {
        if (len < 64)
            break;

        sha256_process(msg, H);

        msg += 64;
        len -= 64;
    }

    uint8_t block[64] = {0};

    memcpy(block, msg, len);
    block[len] = 0x80;

    if (len >= 56) {
        sha256_process(block, H);
        memset(block, 0, sizeof(block));
    }

    block[63] = bitlen & 0xff;
    block[62] = (bitlen >>  8) & 0xff;
    block[61] = (bitlen >> 16) & 0xff;
    block[60] = (bitlen >> 24) & 0xff;
    block[59] = (bitlen >> 32) & 0xff;
    block[58] = (bitlen >> 40) & 0xff;
    block[57] = (bitlen >> 48) & 0xff;
    block[56] = (bitlen >> 56) & 0xff;

    sha256_process(block, H);

    for (uint32_t i = 0; i < 4; ++i) {
        digest[i]      = (H[0] >> (24 - i * 8)) & 0xff;
        digest[i +  4] = (H[1] >> (24 - i * 8)) & 0xff;
        digest[i +  8] = (H[2] >> (24 - i * 8)) & 0xff;
        digest[i + 12] = (H[3] >> (24 - i * 8)) & 0xff;
        digest[i + 16] = (H[4] >> (24 - i * 8)) & 0xff;
        digest[i + 20] = (H[5] >> (24 - i * 8)) & 0xff;
        digest[i + 24] = (H[6] >> (24 - i * 8)) & 0xff;
        digest[i + 28] = (H[7] >> (24 - i * 8)) & 0xff;
    }
}

char *buftohex(uint8_t *buf, uint64_t len)
{
    uint64_t i;
    char *string = malloc(len * 2 + 1);

    for (i = 0; i < len; i++)
        sprintf(string + i * 2, "%02x", buf[i]);
    string[i * 2] = '\0';

    return string;
}

char *base58_encode(uint8_t *msg, uint64_t msglen)
{
    static const char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz";

    int64_t zeroes = 0;

    while (zeroes < msglen && msg[zeroes] == 0)
        zeroes++;

    int64_t size = (msglen - zeroes) * 138 / 100 + 1;
    uint8_t *buf = alloca(size);
    memset(buf, 0, size);

    int64_t i, j = 0, high;
    for (i = zeroes, high = size - 1;
         i < msglen;
         i++, high = j) {

        for (int carry = msg[i], j = size - 1;
             (j > high) || carry;
             j--) {

            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < size && buf[j] == 0; j++)
        ;

    char *str = malloc(zeroes + size - j + 1);

    memset(str, '1', zeroes);

    for (i = zeroes; j < size; i++, j++)
        str[i] = alphabet[buf[j]];
    str[i] = '\0';

    return str;
}

char *base58check_encode(uint8_t version, uint8_t *msg, uint64_t msglen)
{
    uint64_t checksize = 1 + SHA256_SIZE + msglen;
    uint8_t *checkmsg = alloca(checksize);
    uint8_t *hashstart = checkmsg + msglen + 1;

    checkmsg[0] = version;
    memcpy(checkmsg + 1, msg, msglen);

    uint8_t tmphash[SHA256_SIZE];
    sha256_encode(checkmsg, msglen + 1, tmphash);
    sha256_encode(tmphash, sizeof(tmphash), hashstart);

    char *result = base58_encode(checkmsg, 1 + 4 + msglen);

    return result;
}

void secp256k1_privtopub(uint8_t *priv, uint64_t privlen,
                         uint8_t pubkey[SECP256K1_PUB_SIZE])
{
    BIGNUM privnum;
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *pubpoint = EC_POINT_new(curve);

    BN_init(&privnum);
    BN_bin2bn(priv, privlen, &privnum);

    EC_POINT_mul(curve, pubpoint, &privnum, NULL, NULL, NULL);

    EC_POINT_point2oct(curve, pubpoint,
                       POINT_CONVERSION_UNCOMPRESSED,
                       pubkey, SECP256K1_PUB_SIZE, NULL);

    EC_GROUP_free(curve);
    EC_POINT_free(pubpoint);
}


int gen(int argc, char **argv)
{
    uint8_t privkey[SHA256_SIZE];

    if (argc < 2) {
        arc4random_buf(privkey, sizeof(privkey));
    } else {
        sha256_encode((uint8_t *)argv[1], strlen(argv[1]), privkey);
    }

    char *wif = base58check_encode(0x80, privkey, sizeof(privkey));
    printf("WIF: %s\n", wif);
    free(wif);

    uint8_t pubkey[SECP256K1_PUB_SIZE] = {0};
    secp256k1_privtopub(privkey, sizeof(privkey), pubkey);

    char *pubstr = buftohex(pubkey, sizeof(pubkey));
    printf("public key: %s\n", pubstr);
    free(pubstr);

    uint8_t hash[SHA256_SIZE];
    sha256_encode(pubkey, sizeof(pubkey), hash);

    uint8_t binaddr[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(hash, sizeof(hash), binaddr);

    char *address = base58check_encode(0x0, binaddr, sizeof(binaddr));
    printf("address: %s\n", address);
    free(address);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    if (!strcmp(argv[1], "test")) {
        return test();
    } else if (!strcmp(argv[1], "gen")) {
        return gen(argc - 1, argv + 1);
    }

    return 0;
}
