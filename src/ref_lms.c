/* ref_lms.c — driver over the LMS/HSS reference implementation
 * (cisco/hash-sigs, RFC 8554; bundled under src/hash-sigs/).
 *
 * Used only for cross-implementation agreement: verify liboqs LMS
 * signatures under the reference implementation and vice versa, and
 * measure the reference implementation's throughput. Single-level
 * LMS only (levels=1); HSS multi-level trees are not benchmarked.
 * The reference implementation's public-key and signature formats
 * are the HSS framing: a 4-byte levels count prefix followed by the
 * RFC 8554 LMS public key / signature (public key 60 bytes for
 * SHA-256 LMS, signature 2512 bytes for LMS_SHA256_H10_W4) — the
 * same framing liboqs uses, because liboqs vendors this code.
 *
 * Parameter sets are given as H and W, e.g. "10 4" for
 * LMS_SHA256_H10_W4. Supported H: 5, 10, 15, 20, 25. Supported W:
 * 1, 2, 4, 8.
 *
 * Usage:
 *   ref_lms keygen <H> <W>
 *   ref_lms sign <H> <W> <sk-hex> <msg-hex>
 *   ref_lms verify <H> <W> <pk-hex> <msg-hex> <sig-hex>
 *   ref_lms bench <H> <W> <n-keygen> <n-sign> <n-verify>
 * Exit codes: 0 ok, 1 reference error, 2 driver input/length error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "hss.h"
#include "common_defs.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static long unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 != 0) return -1;
    if (n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (long)(n / 2);
}

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *v, size_t n) {
    qsort(v, n, sizeof(double), cmp_double);
    if (n % 2) return v[n / 2];
    return (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static long peak_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long v = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "VmHWM:", 6) == 0) {
            sscanf(line + 6, "%ld", &v);
            break;
        }
    }
    fclose(f);
    return v;
}

static bool rand_bytes(void *output, size_t length) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t n = fread(output, 1, length, f);
    fclose(f);
    return n == length;
}

static int lm_type_for_h(int h) {
    switch (h) {
    case 5: return LMS_SHA256_N32_H5;
    case 10: return LMS_SHA256_N32_H10;
    case 15: return LMS_SHA256_N32_H15;
    case 20: return LMS_SHA256_N32_H20;
    case 25: return LMS_SHA256_N32_H25;
    default: return 0;
    }
}

static int ots_type_for_w(int w) {
    switch (w) {
    case 1: return LMOTS_SHA256_N32_W1;
    case 2: return LMOTS_SHA256_N32_W2;
    case 4: return LMOTS_SHA256_N32_W4;
    case 8: return LMOTS_SHA256_N32_W8;
    default: return 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: ref_lms <cmd> <H> <W> [args...]\n");
        return 2;
    }
    const char *cmd = argv[1];
    int h = atoi(argv[2]), w = atoi(argv[3]);
    param_set_t lm_type = lm_type_for_h(h);
    param_set_t ots_type = ots_type_for_w(w);
    if (!lm_type || !ots_type) {
        printf("ERROR unsupported LMS parameter set H=%d W=%d\n", h, w);
        return 2;
    }
    size_t pk_len = hss_get_public_key_len(1, &lm_type, &ots_type);
    size_t sig_len = hss_get_signature_len(1, &lm_type, &ots_type);
    size_t sk_len = hss_get_private_key_len(1, &lm_type, &ots_type);
    if (!pk_len || !sig_len || !sk_len) {
        printf("ERROR could not determine lengths for H=%d W=%d\n", h, w);
        return 1;
    }

    if (strcmp(cmd, "info") == 0) {
        printf("type LMS-REFERENCE\nlength_public_key %zu\nlength_secret_key %zu\n"
               "length_signature %zu\n",
               pk_len, sk_len, sig_len);
        return 0;
    }

    if (strcmp(cmd, "keygen") == 0) {
        uint8_t *pk = malloc(pk_len);
        uint8_t *sk = malloc(sk_len);
        /* update_private_key NULL + context pointing at the private
         * key buffer: the library writes the key into that buffer. */
        if (!hss_generate_private_key(rand_bytes, 1, &lm_type, &ots_type,
                                      NULL, sk, pk, pk_len, NULL, 0, NULL)) {
            printf("ERROR keypair failed\n"); return 1;
        }
        print_hex("public_key", pk, pk_len);
        print_hex("secret_key", sk, sk_len);
        return 0;
    }

    if (strcmp(cmd, "sign") == 0) {
        if (argc < 6) { printf("ERROR missing secret key or message\n"); return 2; }
        uint8_t *sk = malloc(sk_len);
        long nsk = unhex(argv[4], sk, sk_len);
        if (nsk != (long)sk_len) {
            printf("ERROR secret key length check failed: expected %zu bytes, got %ld\n",
                   sk_len, nsk < 0 ? -1 : nsk);
            return 2;
        }
        size_t msg_cap = strlen(argv[5]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[5], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        struct hss_working_key *wk = hss_load_private_key(NULL, sk, 0, NULL, 0, NULL);
        if (!wk) { printf("ERROR load private key failed\n"); return 1; }
        uint8_t *sg = malloc(sig_len);
        struct hss_extra_info info;
        memset(&info, 0, sizeof info);
        /* update NULL + context=sk: the updated private key is written
         * back into the sk buffer in RAM. */
        if (!hss_generate_signature(wk, NULL, sk, msg, (size_t)nmsg, sg, sig_len, &info)) {
            printf("ERROR sign failed\n"); return 1;
        }
        print_hex("signature", sg, sig_len);
        print_hex("secret_key", sk, sk_len);
        hss_free_working_key(wk);
        return 0;
    }

    if (strcmp(cmd, "verify") == 0) {
        if (argc < 7) { printf("ERROR missing public key, message or signature\n"); return 2; }
        uint8_t *pk = malloc(pk_len);
        long npk = unhex(argv[4], pk, pk_len);
        if (npk != (long)pk_len) {
            printf("ERROR public key length check failed: expected %zu bytes, got %ld\n",
                   pk_len, npk < 0 ? -1 : npk);
            return 2;
        }
        size_t msg_cap = strlen(argv[5]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[5], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        uint8_t *sg = malloc(sig_len);
        long nsg = unhex(argv[6], sg, sig_len);
        if (nsg != (long)sig_len) {
            printf("ERROR signature length check failed: expected %zu bytes, got %ld\n",
                   sig_len, nsg < 0 ? -1 : nsg);
            return 2;
        }
        bool ok = hss_validate_signature(pk, msg, (size_t)nmsg, sg, sig_len, NULL);
        printf("verify %s\n", ok ? "VALID" : "INVALID");
        return 0;
    }

    if (strcmp(cmd, "bench") == 0) {
        int n_keygen = argc >= 5 ? atoi(argv[4]) : 3;
        int n_sign = argc >= 6 ? atoi(argv[5]) : 10;
        int n_verify = argc >= 7 ? atoi(argv[6]) : 10;
        if (n_keygen < 1) n_keygen = 1;
        if (n_sign < 1) n_sign = 1;
        if (n_verify < 1) n_verify = 1;
        const uint8_t msg[] = "benchmark message for hash-sigs throughput measurement";
        size_t mlen = sizeof(msg) - 1;
        int maxn = n_keygen > n_sign ? (n_keygen > n_verify ? n_keygen : n_verify)
                                     : (n_sign > n_verify ? n_sign : n_verify);
        double *t = malloc(sizeof(double) * (size_t)maxn);
        for (int i = 0; i < n_keygen; i++) {
            uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
            double s = now_ms();
            bool ok = hss_generate_private_key(rand_bytes, 1, &lm_type, &ots_type,
                                               NULL, sk, pk, pk_len, NULL, 0, NULL);
            t[i] = now_ms() - s;
            if (!ok) { printf("ERROR keypair failed\n"); return 1; }
            free(pk); free(sk);
        }
        printf("keygen_ms_median %.6f\n", median(t, (size_t)n_keygen));
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        if (!hss_generate_private_key(rand_bytes, 1, &lm_type, &ots_type,
                                      NULL, sk, pk, pk_len, NULL, 0, NULL)) {
            printf("ERROR keypair failed\n"); return 1;
        }
        struct hss_working_key *wk = hss_load_private_key(NULL, sk, 0, NULL, 0, NULL);
        if (!wk) { printf("ERROR load private key failed\n"); return 1; }
        uint8_t *sg = malloc(sig_len);
        int ok_sign = 0;
        for (int i = 0; i < n_sign; i++) {
            struct hss_extra_info info;
            memset(&info, 0, sizeof info);
            double s = now_ms();
            bool ok = hss_generate_signature(wk, NULL, sk, msg, mlen, sg, sig_len, &info);
            t[i] = now_ms() - s;
            if (ok) ok_sign++;
            else { printf("ERROR sign failed at %d\n", i); return 1; }
        }
        printf("sign_ms_median %.6f\n", median(t, (size_t)n_sign));
        printf("sign_ok %d/%d\n", ok_sign, n_sign);
        int ok = 0;
        for (int i = 0; i < n_verify; i++) {
            double s = now_ms();
            bool v = hss_validate_signature(pk, msg, mlen, sg, sig_len, NULL);
            t[i] = now_ms() - s;
            if (v) ok++;
        }
        printf("verify_ms_median %.6f\n", median(t, (size_t)n_verify));
        printf("verify_ok %d/%d\n", ok, n_verify);
        printf("peak_rss_kb %ld\n", peak_rss_kb());
        hss_free_working_key(wk);
        return 0;
    }

    printf("ERROR unknown command %s\n", cmd);
    return 2;
}
