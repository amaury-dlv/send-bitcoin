#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>

#include "bitcoin.h"

#define BUF_INIT  { NULL, 0 }

typedef struct buf_t {
    uint8_t *data;
    uint64_t len;
} buf_t;

typedef struct bufsec_t {
    char *name;
    int size;
} bufsec_t;

typedef struct txin_t {
    uint8_t prevhash[32];
    uint32_t previndex;
    buf_t scriptsig;
} txin_t;

typedef struct txout_t {
    int64_t txvalue;
    buf_t pkscript;
} txout_t;

typedef struct tx_t {
    uint32_t version;
    uint64_t incount;;
    txin_t *inputs;
    uint64_t outcount;
    txout_t *outputs;
    uint32_t locktime;
} tx_t;

typedef struct __attribute__((packed)) msghdr_t {
    uint32_t magic;
    char cmd[12];
    uint32_t length;
    uint32_t checksum;
} msghdr_t;

typedef struct cmdhandler_t {
    char *cmd;
    void (*func)(int sockfd, msghdr_t *header, uint8_t *payload, int incoming);
} cmdhandler_t;

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

    while (len >= 64) {
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

void ecdsa_sign(uint8_t *msg, uint64_t len, uint8_t *privkey, uint8_t *sig)
{
    BIGNUM privnum;
    BN_init(&privnum);
    BN_bin2bn(privkey, PRIVKEY_SIZE, &privnum);

    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_secp256k1);

    EC_KEY_set_group(eckey, curve);
    EC_KEY_set_private_key(eckey, &privnum);

    ECDSA_SIG *esig = ECDSA_do_sign(msg, len, eckey);

    int verify = ECDSA_do_verify(msg, len, esig, eckey);
    if (!verify)
        errx("couldn't sign message");

    i2d_ECDSA_SIG(esig, &sig);
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

void hash160_encode(uint8_t *msg, uint64_t len, uint8_t hash[HASH160_SIZE])
{
    uint8_t s256[SHA256_SIZE];

    sha256_encode(msg, len, s256);
    RIPEMD160(s256, sizeof(s256), hash);
}

uint8_t *hextobuf(char *hex, uint64_t *buflen)
{
    uint64_t size = (strlen(hex) / 2) + (strlen(hex) % 2);
    uint8_t *buf = malloc(size);

    memset(buf, 0, size);

    for (uint64_t i = 0; i < strlen(hex); i++) {
        uint8_t v;
        char c = hex[i];

        if (c >= 'a' && c <= 'z')
            v = 10 + c - 'a';
        else if (c >= 'A' && c <= 'Z')
            v = 10 + c - 'A';
        else if (c >= '0' && c <= '9')
            v = c - '0';
        else
            errx("invalid hex string: %s", hex);

        buf[i / 2] |= (v << (4 * (i % 2 == 0)));
    }

    if (buflen)
        *buflen = size;

    return buf;
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


void help(void)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  send-bitcoin help\n");
    fprintf(stderr, "  send-bitcoin gen [passphrase]\n");
    fprintf(stderr, "  send-bitcoin info <private key>\n");
    fprintf(stderr, "  send-bitcoin send -p <src private key>"
                    " -d <dst public key> -o <output hash>"
                    " -v <satoshis> -i <output index>\n");

    exit(1);
}

int gen(int argc, char **argv)
{
    uint8_t privkey[SHA256_SIZE];

    if (argc < 2)
        arc4random_buf(privkey, sizeof(privkey));
    else
        sha256_encode((uint8_t *)argv[1], strlen(argv[1]), privkey);

    char *wif = base58check_encode(0x80, privkey, sizeof(privkey));
    printf("WIF: %s\n", wif);
    free(wif);

    uint8_t pubkey[SECP256K1_PUB_SIZE] = {0};
    secp256k1_privtopub(privkey, sizeof(privkey), pubkey);

    char *pubstr = buftohex(pubkey, sizeof(pubkey));
    printf("public key: %s\n", pubstr);
    free(pubstr);

    uint8_t binaddr[HASH160_SIZE];
    hash160_encode(pubkey, sizeof(pubkey), binaddr);

    char *address = base58check_encode(0x0, binaddr, sizeof(binaddr));
    printf("address: %s\n", address);
    free(address);

    return 0;
}

int info(int argc, char **argv)
{
    return 0;
}

void buf_init(buf_t *buf)
{
    buf->data = NULL;
    buf->len = 0;
}

void buf_reset(buf_t *buf)
{
    free(buf->data);

    buf_init(buf);
}

void buf_append(buf_t *buf, void *data, uint64_t size)
{
    uint64_t oldlen = buf->len;

    buf->len += size;
    buf->data = realloc(buf->data, buf->len);
    memcpy(buf->data + oldlen, data, size);
}

void buf_append_u8(buf_t *buf, uint8_t v)
{
    buf_append(buf, &v, sizeof(v));
}

void buf_append_u16n(buf_t *buf, uint16_t v)
{
    uint16_t vn = 0;

    vn |= (v >> 8) & 0x00ff;
    vn |= (v << 8) & 0xff00;

    buf_append(buf, &vn, sizeof(vn));
}

void buf_append_u32(buf_t *buf, uint32_t v)
{
    buf_append(buf, &v, sizeof(v));
}

void buf_append_u64(buf_t *buf, uint64_t v)
{
    buf_append(buf, &v, sizeof(v));
}

void buf_append_varint(buf_t *buf, uint64_t v)
{
    if (v >= 0xfd)
        errx("unsupported varint: %llx", v);

    buf_append_u8(buf, v & 0xff);
}

void buf_append_varstr(buf_t *buf, char *str)
{
    buf_append_varint(buf, strlen(str));
    buf_append(buf, str, strlen(str));
}

void buf_append_buf(buf_t *buf, buf_t *d)
{
    buf_append(buf, d->data, d->len);
}

void buf_append_nwaddr(buf_t *buf, char *ip)
{
    uint8_t addr[16] = {0};

    addr[10] = 0xff;
    addr[11] = 0xff;

    inet_pton(AF_INET, ip, addr + 12);

    buf_append_u64(buf, SERVICES);
    buf_append(buf, addr, sizeof(addr));
    buf_append_u16n(buf, PORTN);
}

void buf_dump(buf_t *buf, bufsec_t sections[])
{
    uint64_t i = 0, sec = 0;

    while (i < buf->len) {
        char *secname;
        uint64_t j;

        if (sections[sec].name) {
            secname = sections[sec].name;
            j = sections[sec].size;
            if (j > buf->len) j = buf->len;
            sec++;
        } else {
            secname = "<trailing>";
            j = buf->len - i;
        }

        char *hex = buftohex(&buf->data[i], j);
        printf("%s\n    %s\n", secname, hex);
        free(hex);

        i += j;
    }
}

void txin_init(txin_t *txin, uint8_t *prevout, unsigned previndex)
{
    memset(txin, 0, sizeof(*txin));

    memcpy(txin->prevhash, prevout, sizeof(txin->prevhash));
    txin->previndex = previndex;
}

void txin_serialize(txin_t *txin, buf_t *out)
{
    char revouthash[32];

    for (unsigned i = 0; i < sizeof(txin->prevhash); i++)
        revouthash[i] = txin->prevhash[sizeof(txin->prevhash) - i - 1];

    buf_append(out, revouthash, sizeof(revouthash));
    buf_append_u32(out, txin->previndex);

    buf_append_varint(out, txin->scriptsig.len);
    buf_append_buf(out, &txin->scriptsig);
    buf_append_u32(out, 0xffffffff);
}

void txout_init(txout_t *txout, uint64_t value)
{
    memset(txout, 0, sizeof(*txout));

    txout->txvalue = value;
}

void txout_serialize(txout_t *txout, buf_t *out)
{
    buf_append_u64(out, txout->txvalue);
    buf_append_varint(out, txout->pkscript.len);
    buf_append_buf(out, &txout->pkscript);
}

void tx_init(tx_t *tx)
{
    memset(tx, 0, sizeof(*tx));

    tx->version = 0x01;
    tx->locktime = 0;
}

void tx_serialize(tx_t *tx, buf_t *out)
{
    buf_append_u32(out, tx->version);

    buf_append_varint(out, tx->incount);
    for (unsigned i = 0; i< tx->incount; i++)
        txin_serialize(&tx->inputs[i], out);

    buf_append_varint(out, tx->outcount);
    for (unsigned i = 0; i < tx->outcount; i++)
        txout_serialize(&tx->outputs[i], out);

    buf_append_u32(out, tx->locktime);
}

void tx_set_input(tx_t *tx, txin_t *txin)
{
    tx->incount = 1;
    tx->inputs = txin;
}

void tx_set_output(tx_t *tx, txout_t *txout)
{
    tx->outcount = 1;
    tx->outputs = txout;
}

void tx_sign(tx_t *tx, buf_t *bin, uint8_t *privkey, uint8_t *sig)
{
    uint8_t s256_1[SHA256_SIZE];
    uint8_t s256_2[SHA256_SIZE];

    sha256_encode(bin->data, bin->len, s256_1);
    sha256_encode(s256_1, sizeof(s256_1), s256_2);

    ecdsa_sign(s256_2, sizeof(s256_2), privkey, sig);
}

void make_scriptpubkey(buf_t *script, uint8_t *pubkey)
{
    uint8_t pubkeyhash[HASH160_SIZE];

    buf_append_u8(script, 0x76); // DUP
    buf_append_u8(script, 0xa9); // HASH160
    buf_append_u8(script, 0x14); // PUSHDATA

    hash160_encode(pubkey, PUBKEY_SIZE, pubkeyhash);
    buf_append(script, pubkeyhash, sizeof(pubkeyhash));

    buf_append_u8(script, 0x88); // EQUALVERIFY
    buf_append_u8(script, 0xac); // CHECKSIG
}

void make_scriptsig(buf_t *script, uint8_t *sig, uint8_t *pubkey)
{
    buf_append_u8(script, 0x47); // PUSHDATA

    buf_append(script, sig, DERSIG_SIZE);

    buf_append_u8(script, 0x01);
    buf_append_u8(script, 0x41); // PUSHDATA

    buf_append(script, pubkey, PUBKEY_SIZE);
}

void make_signedtx(uint8_t *privkey, uint8_t *pubkey, uint8_t *prevhash,
                   unsigned previndex, uint64_t satoshis, buf_t *out)
{
    txin_t txin;
    txin_init(&txin, prevhash, previndex);

    uint8_t srcpubkey[PUBKEY_SIZE];
    secp256k1_privtopub(privkey, PRIVKEY_SIZE, srcpubkey);
    make_scriptpubkey(&txin.scriptsig, srcpubkey);

    txout_t txout;
    txout_init(&txout, satoshis);

    make_scriptpubkey(&txout.pkscript, pubkey);

    tx_t tx;
    tx_init(&tx);
    tx_set_input(&tx, &txin);
    tx_set_output(&tx, &txout);

    buf_t buftosign = BUF_INIT;
    tx_serialize(&tx, &buftosign);
    buf_append_u32(&buftosign, 0x00000001);

    uint8_t signature[DERSIG_SIZE];
    tx_sign(&tx, &buftosign, privkey, signature);

    buf_reset(&txin.scriptsig);
    make_scriptsig(&txin.scriptsig, signature, pubkey);

    tx_serialize(&tx, out);
}

void make_version(buf_t *out)
{
    buf_append_u32(out, 70001);                // version
    buf_append_u64(out, SERVICES);             // services
    buf_append_u64(out, (unsigned)time(NULL)); // timestamp

    buf_append_nwaddr(out, "127.0.0.1");       // addr_recv
    buf_append_nwaddr(out, "127.0.0.1");       // addr_from

    uint64_t nonce = (((uint64_t)arc4random() << 32) | arc4random());
    buf_append_u64(out, nonce);                // nonce
    buf_append_varstr(out, "send-bitcoin");    // user-agent
    buf_append_u32(out, 0);                    // height
    buf_append_u8(out, 0xff);                  // relay
}

void make_pong(buf_t *out, uint64_t nonce)
{
    buf_append_u64(out, nonce);
}

void make_msg(char *cmd, buf_t *payload, buf_t *out)
{
    uint8_t checksum0[SHA256_SIZE];
    uint8_t checksum1[SHA256_SIZE];
    char cmdbuf[12] = {0};

    sha256_encode(payload->data, payload->len, checksum0);
    sha256_encode(checksum0, sizeof(checksum0), checksum1);

    memcpy(cmdbuf, cmd, strlen(cmd));

    buf_append_u32(out, MAIN_MAGIC);         // magic
    buf_append(out, cmdbuf, sizeof(cmdbuf)); // command
    buf_append_u32(out, payload->len);       // length
    buf_append(out, checksum1, 4);           // checksum
    buf_append_buf(out, payload);            // payload
}

void handle_version(int sockfd, msghdr_t *header,
                    uint8_t *payload, int incoming)
{
    char useragent[1024] = {0};

    memcpy(useragent, payload + 81, payload[80]);
    printf("user-agent:%s", useragent);

    if (incoming) {
        buf_t verack = BUF_INIT, verackmsg = BUF_INIT;
        make_msg("verack", &verack, &verackmsg);

        printf("\n");
        peer_sendmsg(sockfd, &verackmsg);
    }
}

void handle_alert(int sockfd, msghdr_t *header, uint8_t *payload, int incoming)
{
    char *hex = buftohex(payload, header->length);
    printf("message:%s", hex);
    free(hex);
}

void handle_ping(int sockfd, msghdr_t *header, uint8_t *payload, int incoming)
{
    uint64_t nonce = *(uint64_t *)payload;

    if (incoming) {
        buf_t pongpl = BUF_INIT, pongmsg = BUF_INIT;

        make_pong(&pongpl, nonce);
        make_msg("pong", &pongpl, &pongmsg);

        printf("\n");
        peer_sendmsg(sockfd, &pongmsg);
    }
}

void handle_inv(int sockfd, msghdr_t *header, uint8_t *payload, int incoming)
{
    printf("#:%u", *payload);
}

cmdhandler_t handlers[] = {
    { "version", handle_version },
    { "alert",   handle_alert },
    { "ping",    handle_ping },
    { "inv",     handle_inv },
    { NULL, NULL },
};

void handle_cmd(int sockfd, msghdr_t *header, uint8_t *payload, int incoming)
{
    printf("%c %s ", incoming ? '<' : '>', header->cmd);

    for (unsigned i = 0; handlers[i].cmd; i++)
        if (!strcmp(header->cmd, handlers[i].cmd)) {
            handlers[i].func(sockfd, header, payload, incoming);
            break;
        }

    printf("\n");
}

void peer_recv(int sockfd, void *buf, size_t length)
{
    ssize_t rc;

    rc = recv(sockfd, buf, length, MSG_WAITALL);

    if (rc < 0)
        perror("recv");

    if (rc != length)
        errx("recv failure");
}

void peer_sendmsg(int sockfd, buf_t *msg)
{
    ssize_t rc;
    msghdr_t *header;

    header = (msghdr_t *)msg->data;

    handle_cmd(sockfd, header, msg->data + sizeof(*header), 0);

    rc = send(sockfd, msg->data, msg->len, 0);

    if (rc < 0)
        perror("send");

    if (rc != msg->len)
        errx("send failure (%lu)", rc);
}

void peer_rcvmsg(int sockfd)
{
    msghdr_t header;

    peer_recv(sockfd, &header, sizeof(header));

    uint8_t *payload = malloc(header.length);
    peer_recv(sockfd, payload, header.length);

    handle_cmd(sockfd, &header, payload, 1);

    free(payload);
}

int sendtransac(int argc, char **argv)
{
    int opt;
    uint64_t privlen, publen, prevhashlen;
    uint8_t *privkey = NULL, *pubkey = NULL, *prevhash = NULL;
    uint32_t outputindex = 0, satoshis = 0;

    while ((opt = getopt(argc, argv, "p:d:o:i:v:")) != -1) {
        switch (opt) {
        case 'p':
            privkey = hextobuf(optarg, &privlen);
            break;
        case 'd':
            pubkey = hextobuf(optarg, &publen);
            break;
        case 'o':
            prevhash = hextobuf(optarg, &prevhashlen);
            break;
        case 'i':
            outputindex = atoi(optarg);
            break;
        case 'v':
            satoshis = atoi(optarg);
            break;
        default:
            help();
            break;
        }
    }

    if (!privlen || !publen || !prevhashlen || !satoshis)
      help();

    if (privlen != PRIVKEY_SIZE || publen != PUBKEY_SIZE || prevhashlen != 32)
      errx("invalid key format");

    buf_t signedtx = BUF_INIT;

    make_signedtx(privkey, pubkey, prevhash, outputindex, satoshis, &signedtx);

    printf("size: %lld\n", signedtx.len);
    printf("payload: %s\n\n", buftohex(signedtx.data, signedtx.len));

    buf_t msg = BUF_INIT;

    make_msg("tx", &signedtx, &msg);

#if 1
    bufsec_t txsects[] = {
        { "Magic",          4 },
        { "Command",       12 },
        { "Length",         4 },
        { "Checksum",       4 },
        { "Tx-version",     4 },
        { "Input-count",    1 },
        { " Prev-Hash",    32 },
        { " Prev-Index",    4 },
        { " Script-Length", 1 },
        { " ScriptSig",     1 },
        { "  Signature",   70 },
        { "  Hash-Push",    2 },
        { "  Hash-type",   65 },
        { " Sequence",      4 },
        { "Output-count",   1 },
        { " Satoshis",      8 },
        { " Script-Length", 1 },
        { " ScriptPubKey",  3 },
        { "  Pubkey-hash", 20 },
        { "  Verif-Check",  2 },
        { "Locktime",       4 },
        { NULL, 0 },
    };

    printf("TRANSACTION:\n");
    buf_dump(&msg, txsects);
    printf("\n");
#endif


    buf_t versionpl = BUF_INIT;
    make_version(&versionpl);

    buf_t versionmsg = BUF_INIT;
    make_msg("version", &versionpl, &versionmsg);

#if 1
    bufsec_t versionsects[] = {
        { "Magic",      4 },
        { "Command",   12 },
        { "Length",     4 },
        { "Checksum",   4 },
        { "Version",    4 },
        { "Services",   8 },
        { "Timestamp",  8 },
        { "Addr-recv", 26 },
        { "Addr-from", 26 },
        { "Nonce",      8 },
        { "User-agent",13 },
        { "Height",     4 },
        { "Relay",      1 },
        { NULL,         0 },
    };

    printf("VERSION:\n");
    buf_dump(&versionmsg, versionsects);
    printf("\n");
#endif

    int sockfd, rc;
    char *peerip = "71.202.109.111";

    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(peerip, PORT, &hints, &servinfo);
    if (rc != 0)
        errx("getaddrinfo failed");

    printf("connecting to %s\n", peerip);

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }

        rc = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (rc == -1) {
            close(sockfd);
            perror("connect");
        }

        break;
    }

    if (p == NULL)
        errx("failed to connect");

    printf("connected!\n");

    peer_sendmsg(sockfd, &versionmsg);

    for (;;)
        peer_rcvmsg(sockfd);

    free(privkey);
    free(pubkey);
    free(prevhash);

    return 0;
}

void errx(char *fmt, ...)
{
    va_list valist;

    char *errstr;
    asprintf(&errstr, "error: %s\n", fmt);

    va_start(valist, fmt);
    vfprintf(stderr, errstr, valist);
    va_end(valist);

    free(errstr);

    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        help();

    argc--;
    argv++;

    if (!strcmp(argv[0], "test"))
        return test();
    else if (!strcmp(argv[0], "gen"))
        return gen(argc, argv);
    else if (!strcmp(argv[0], "info"))
        return info(argc, argv);
    else if (!strcmp(argv[0], "send"))
        return sendtransac(argc, argv);
    else
        help();

    return 0;
}
