#ifndef BITCOIN_H_
#define BITCOIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SHA256_SIZE        32
#define SECP256K1_PUB_SIZE 65
#define DERSIG_SIZE        70
#define PRIVKEY_SIZE       32
#define PUBKEY_SIZE        65
#define HASH160_SIZE       20

#define MAIN_MAGIC         0xD9B4BEF9
#define SERVICES           0x1
#define PORT               8333
#define PORTSTR            "8333"
#define DNSSEED            "dnsseed.bitcoin.dashjr.org"
#define SATOSHIS_PER_BTC   100000000

struct buf_t;

void errx(char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

void sha256_encode(uint8_t *msg, uint64_t len,
                   uint8_t result[SHA256_SIZE]);

char *base58_encode(uint8_t *msg, uint64_t msglen);
char *base58check_encode(uint8_t version, uint8_t *msg,
                         uint64_t msglen);

void secp256k1_privtopub(uint8_t *priv, uint64_t privlen,
                         uint8_t pubkey[SECP256K1_PUB_SIZE]);

char *buftohex(uint8_t *buf, uint64_t len);
uint8_t *hextobuf(char *hex, uint64_t *buflen);

void peer_sendmsg(int sockfd, struct buf_t *msg);

int test(void);

#endif
