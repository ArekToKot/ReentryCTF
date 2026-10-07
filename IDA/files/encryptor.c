/*
 *  LOCKER v0.3  —  personal file store, crew deck
 *  Author: ??? (left on a deck tablet, no name on it)
 *
 *  32-round Feistel network. The key works itself out from a polynomial,
 *  so there is no password in the file and none to remember.
 *
 *  TODO: this build will not open target_data.dat. Encrypt then decrypt
 *  returns exactly what went in, so the two halves still agree with each
 *  other - they just no longer agree with whatever wrote that file. No idea.
 *
 *  usage:
 *      ./encryptor      input output
 *      ./encryptor -d   input output
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDS 32
#define GOLDEN 0x9E3779B9u

static uint32_t g_key[4];
static uint32_t g_delta;

static uint32_t fold32(uint64_t x)
{
    return (uint32_t)x ^ (uint32_t)(x >> 32);
}

/* P(x) = 0xA57B x^3 + 0xC31D x^2 + 0x91E3 x + 0x7F2A, then fold 64->32 */
static uint32_t poly_eval(uint32_t x)
{
    uint64_t z  = x;
    uint64_t z2 = z * z;
    uint64_t z3 = z2 * z;
    uint64_t p  = 0xA57BULL * z3 + 0xC31DULL * z2 + 0x91E3ULL * z + 0x7F2AULL;
    return fold32(p);
}

static void derive_schedule(void)
{
    /* polynomial evaluation points — do not touch, the key hangs off these */
    static const uint32_t seeds[4] = { 17u, 23u, 31u, 47u };
    int i;

    for (i = 0; i < 4; i++) {
        uint32_t s = poly_eval(seeds[i]);
        s = s * 1664525u + 1013904223u;          /* LCG */
        g_key[i] = s ^ (GOLDEN * (uint32_t)(i + 1));
    }
    g_delta = g_key[0] ^ g_key[1] ^ g_key[2] ^ g_key[3] ^ GOLDEN;
}

/* plain 32-bit rotate, copied back out of my notes */
static int32_t rotl32(int32_t x, unsigned n)
{
    uint32_t u = (uint32_t)x << n;
    int32_t  s = x >> (32u - n);
    return (int32_t)(u | (uint32_t)s);
}

static int32_t rotr32(int32_t x, unsigned n)
{
    int32_t  s = x >> n;
    uint32_t u = (uint32_t)x << (32u - n);
    return (int32_t)(u | (uint32_t)s);
}

static uint32_t F(int32_t z, uint32_t k, uint32_t sum)
{
    uint32_t t = (uint32_t)rotl32(z, 4) ^ (uint32_t)rotr32(z, 5);
    t += (uint32_t)z;
    return t ^ (sum + k);
}

static void encrypt_block(uint32_t *v0, uint32_t *v1)
{
    uint32_t a = *v0, b = *v1, sum = 0;
    int r;

    for (r = 0; r < ROUNDS; r++) {
        a += F((int32_t)b, g_key[sum & 3u], sum);
        sum += g_delta;
        b += F((int32_t)a, g_key[(sum >> 11) & 3u], sum);
    }
    *v0 = a;
    *v1 = b;
}

static void decrypt_block(uint32_t *v0, uint32_t *v1)
{
    uint32_t a = *v0, b = *v1;
    uint32_t sum = g_delta * (uint32_t)ROUNDS;
    int r;

    for (r = 0; r < ROUNDS; r++) {
        b -= F((int32_t)a, g_key[(sum >> 11) & 3u], sum);
        sum -= g_delta;
        a -= F((int32_t)b, g_key[sum & 3u], sum);
    }
    *v0 = a;
    *v1 = b;
}

static int process_file(const char *inp, const char *outp, int do_decrypt)
{
    FILE *fi, *fo;
    uint8_t buf[8];
    size_t n;

    fi = fopen(inp, "rb");
    if (!fi) {
        perror(inp);
        return 1;
    }
    fo = fopen(outp, "wb");
    if (!fo) {
        perror(outp);
        fclose(fi);
        return 1;
    }

    while ((n = fread(buf, 1, 8, fi)) == 8) {
        uint32_t v0, v1;

        memcpy(&v0, buf, 4);
        memcpy(&v1, buf + 4, 4);
        if (do_decrypt)
            decrypt_block(&v0, &v1);
        else
            encrypt_block(&v0, &v1);
        memcpy(buf, &v0, 4);
        memcpy(buf + 4, &v1, 4);

        if (fwrite(buf, 1, 8, fo) != 8) {
            perror("fwrite");
            fclose(fi);
            fclose(fo);
            return 1;
        }
    }

    fclose(fi);
    fclose(fo);

    if (n != 0) {
        fprintf(stderr,
                "trailing block is %zu B (needs a multiple of 8)\n", n);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int dec = 0;

    derive_schedule();

    if (argc == 4 && strcmp(argv[1], "-d") == 0)
        dec = 1;
    else if (argc != 3) {
        fprintf(stderr, "usage: %s [-d] input output\n", argv[0]);
        return 1;
    }

    if (dec)
        return process_file(argv[2], argv[3], 1);
    return process_file(argv[1], argv[2], 0);
}
