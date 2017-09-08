#include "bitcoin.h"

static int test_sha256()
{
    int err = 0;

    uint8_t sha256[SHA256_SIZE];
    char *str;

    sha256_encode((uint8_t *)"abc", 3, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    free(str);

    sha256_encode((uint8_t *)"qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty", 56, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "45af198c730b5bbb42a997cd2b14c1364995a8d3210a4ce91ca7a3cac451c9f0");
    free(str);

    sha256_encode((uint8_t *)"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii", 63, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "95791dbc15f57efffe740116d876928bbd383aef1186bb88b46d849a7066ef9b");
    free(str);


    sha256_encode((uint8_t *)"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii", 64, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "a343b617ce1070a37251a5e66b409947ec3d3ff7d89b9de482d7df84402778d2");
    free(str);

    sha256_encode((uint8_t *)
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            , 56 * 3, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "b3b92da0d8c10cf435676e3cfd7d5992caf3fb53fc1418d11f2b20c000eb7872");
    free(str);

    sha256_encode((uint8_t *)
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
            , 56 * 8, sha256);
    str = buftohex(sha256, sizeof(sha256));
    err = err || strcmp(str, "06289543043e585ec04f756f971ef8ceda1577ca5344b69a30c829a81a626cfb");
    free(str);

    return err;
}

static int test_base58()
{
    int err = 0;
    char *res;

    res = base58_encode((uint8_t *)"a", 1);
    err = err || strcmp(res, "2g");
    free(res);

    res = base58_encode((uint8_t *)"abc", 3);
    err = err || strcmp(res, "ZiCa");
    free(res);

    res = base58_encode((uint8_t *)"qwertyuiopqwertyuiop", 20);
    err = err || strcmp(res, "2agjfoWbNPGS3tMXRsKAK3PkDCh5");
    free(res);

    return err;
}

static int test_base58check()
{
    int err = 0;
    char *res;
    uint8_t sha256[SHA256_SIZE];

    sha256_encode((uint8_t *)"aaaaaaaaaaaaaaaa", 16, sha256);
    res = base58check_encode(0x80, sha256, sizeof(sha256));
    err = err || strcmp(res, "5HubJ2xgcnt244PH7gs1G63yWrLetPGjVoELTMahmPL6yw9jnEu");
    free(res);

    sha256_encode((uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26, sha256);
    res = base58check_encode(0x80, sha256, sizeof(sha256));
    err = err || strcmp(res, "5JgPd2TjTgsfUBqhwJS53Q8nKyYhxvprFEUpDtXk67waaRWeYKq");
    free(res);

    sha256_encode((uint8_t *)
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            , 26 * 4, sha256);
    res = base58check_encode(0x80, sha256, sizeof(sha256));
    err = err || strcmp(res, "5JwWiKvNTV8MWtEUXSKVb2wqXpEKXi2TXbc2bgC8yisQutkbUtC");
    free(res);

    return err;
}

int test_secp256k1(void)
{
    int err = 0;
    uint8_t privkey[SHA256_SIZE];
    uint8_t pubkey[SECP256K1_PUB_SIZE];

    sha256_encode((uint8_t *)"aaaaaaaaaaaaaaaa", 16, privkey);
    secp256k1_privtopub(privkey, sizeof(privkey), pubkey);

    char *expected = "04"
        "1d06fb5e9bfdfd9ea1ff1eb97be76f7dcb88c23ce8e0f4ab57394572445a847b"
        "ca075746d686ec4b622362b01080c3585b32c5f1742ffb326073984349456419";
    char *actual = buftohex(pubkey, sizeof(pubkey));

    err = err || strcmp(expected, actual);

    free(actual);

    return err;
}

int test(void)
{
    int err = 0;

    int sha256err = test_sha256();
    printf("sha256:\t\t%s\n", sha256err ? "failed" : "ok");
    err = err || sha256err;

    int base58err = test_base58();
    printf("base58:\t\t%s\n", base58err ? "failed" : "ok");
    err = err || base58err;

    int base58checkerr = test_base58check();
    printf("base58check:\t%s\n", base58checkerr ? "failed" : "ok");
    err = err || base58checkerr;

    int secp256k1err = test_secp256k1();
    printf("secp256k1:\t%s\n", secp256k1err ? "failed" : "ok");
    err = err || secp256k1err;

    if (err) {
        return 1;
    }

    return 0;
}
