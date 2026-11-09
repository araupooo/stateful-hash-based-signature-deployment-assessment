/* pq_driver.c — minimal stdin/argv driver over liboqs 0.16.0.
 *
 * Covers ML-DSA-44/65/87 and all 12 FIPS 205 SLH-DSA parameter sets
 * through the generic OQS_SIG API. (No KEM commands: this pack signs
 * only.) All inputs and outputs are hex on stdout, one
 * labelled line each, so the Python harness can drive it without parsing
 * binary. The driver validates every buffer length against the
 * algorithm's published lengths BEFORE calling liboqs: liboqs itself
 * takes bare pointers and performs no length checks of its own
 * (see findings.md, F-02). A length violation is reported as
 * "ERROR <message>" on stdout and exit code 2; it never reaches liboqs.
 *
 * Usage:
 *   pq_driver info <alg>
 *   pq_driver sig-keygen <alg>
 *   pq_driver sig-sign <alg> <sk-hex> <msg-hex> [ctx-hex]
 *   pq_driver sig-sign-twice <alg> <sk-hex> <msg-hex>
 *   pq_driver sig-verify <alg> <pk-hex> <msg-hex> <sig-hex> [ctx-hex]
 *   pq_driver sig-bench <alg> <n>
 *
 * Exit codes: 0 ok, 1 liboqs error, 2 driver input/length error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns byte count, or -1 on bad hex. */
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

/* Peak RSS in kilobytes, read from /proc/self/status VmHWM.
 * NOTE: getrusage(RUSAGE_SELF).ru_maxrss is NOT per-process in this
 * environment — a child spawned from Python reports the parent Python
 * process's peak instead of its own (verified: a trivial test program
 * reports ~1 MB direct but ~11 MB when spawned from Python, exactly the
 * parent's value). VmHWM is the process's own high-water mark and is
 * parent-independent, so it is used here instead. */
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

static int is_sig(const char *alg) {
    return strncmp(alg, "ML-DSA-", 7) == 0 || strncmp(alg, "SLH-DSA-", 8) == 0 ||
           strncmp(alg, "SLH_DSA_PURE_", 13) == 0;
}

/* liboqs 0.16.0 identifies the FIPS 205 pure SLH-DSA parameter sets by
 * its own names (SLH_DSA_PURE_SHA2_128S, ...), not the FIPS 205 names
 * (SLH-DSA-SHA2-128s, ...). Translate so the harness can use FIPS names. */
static const char *resolve_alg(const char *alg) {
    static const char *fips[12] = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"};
    static const char *oqs[12] = {
        "SLH_DSA_PURE_SHA2_128S", "SLH_DSA_PURE_SHA2_128F",
        "SLH_DSA_PURE_SHA2_192S", "SLH_DSA_PURE_SHA2_192F",
        "SLH_DSA_PURE_SHA2_256S", "SLH_DSA_PURE_SHA2_256F",
        "SLH_DSA_PURE_SHAKE_128S", "SLH_DSA_PURE_SHAKE_128F",
        "SLH_DSA_PURE_SHAKE_192S", "SLH_DSA_PURE_SHAKE_192F",
        "SLH_DSA_PURE_SHAKE_256S", "SLH_DSA_PURE_SHAKE_256F"};
    for (int i = 0; i < 12; i++)
        if (strcmp(alg, fips[i]) == 0) return oqs[i];
    return alg;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pq_driver <cmd> <alg> [args...]\n");
        return 2;
    }
    const char *cmd = argv[1];
    const char *alg = resolve_alg(argv[2]);
    if (!is_sig(alg)) {
        printf("ERROR unknown algorithm %s\n", alg);
        return 2;
    }

    if (strcmp(cmd, "info") == 0) {
        OQS_SIG *sig0 = OQS_SIG_new(alg);
        if (!sig0) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
        printf("type SIG\nlength_public_key %zu\nlength_secret_key %zu\n"
               "length_signature %zu\n",
               sig0->length_public_key, sig0->length_secret_key,
               sig0->length_signature);
        OQS_SIG_free(sig0);
        return 0;
    }

    /* --- signatures --- */
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
    size_t pk_len = sig->length_public_key, sk_len = sig->length_secret_key;
    size_t sig_len = sig->length_signature;

    if (strcmp(cmd, "sig-keygen") == 0) {
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
            printf("ERROR keypair failed\n"); return 1;
        }
        print_hex("public_key", pk, pk_len);
        print_hex("secret_key", sk, sk_len);
        return 0;
    }
    if (strcmp(cmd, "sig-sign") == 0 || strcmp(cmd, "sig-sign-twice") == 0) {
        if (argc < 5) { printf("ERROR missing secret key or message\n"); return 2; }
        uint8_t *sk = malloc(sk_len);
        long nsk = unhex(argv[3], sk, sk_len);
        if (nsk != (long)sk_len) {
            printf("ERROR secret key length check failed: expected %zu bytes, got %ld\n",
                   sk_len, nsk < 0 ? -1 : nsk);
            return 2;
        }
        size_t msg_cap = strlen(argv[4]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[4], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;
        uint8_t *ctxbuf = NULL;
        if (argc >= 6) {
            ctxbuf = malloc(strlen(argv[5]) / 2 + 1);
            long nctx = unhex(argv[5], ctxbuf, strlen(argv[5]) / 2 + 1);
            if (nctx < 0) { printf("ERROR bad context hex\n"); return 2; }
            ctx = ctxbuf; ctx_len = (size_t)nctx;
        }
        uint8_t *sg = malloc(sig_len);
        size_t sg_len = 0;
        OQS_STATUS st;
        if (ctx) st = OQS_SIG_sign_with_ctx_str(sig, sg, &sg_len, msg, (size_t)nmsg, ctx, ctx_len, sk);
        else     st = OQS_SIG_sign(sig, sg, &sg_len, msg, (size_t)nmsg, sk);
        if (st != OQS_SUCCESS) {
            printf("ERROR sign failed status %d\n", (int)st);
            return 1;
        }
        print_hex("signature", sg, sg_len);
        if (strcmp(cmd, "sig-sign-twice") == 0) {
            uint8_t *sg2 = malloc(sig_len);
            size_t sg2_len = 0;
            if (ctx) st = OQS_SIG_sign_with_ctx_str(sig, sg2, &sg2_len, msg, (size_t)nmsg, ctx, ctx_len, sk);
            else     st = OQS_SIG_sign(sig, sg2, &sg2_len, msg, (size_t)nmsg, sk);
            if (st != OQS_SUCCESS) {
                printf("ERROR second sign failed status %d\n", (int)st);
                return 1;
            }
            print_hex("signature2", sg2, sg2_len);
            printf("signatures_identical %s\n",
                   (sg_len == sg2_len && memcmp(sg, sg2, sg_len) == 0) ? "yes" : "no");
        }
        return 0;
    }
    if (strcmp(cmd, "sig-verify") == 0) {
        if (argc < 6) { printf("ERROR missing public key, message or signature\n"); return 2; }
        uint8_t *pk = malloc(pk_len);
        long npk = unhex(argv[3], pk, pk_len);
        if (npk != (long)pk_len) {
            printf("ERROR public key length check failed: expected %zu bytes, got %ld\n",
                   pk_len, npk < 0 ? -1 : npk);
            return 2;
        }
        size_t msg_cap = strlen(argv[4]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[4], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        /* Signature length is checked against the algorithm's length;
         * a truncated or over-long signature is refused here, before liboqs. */
        size_t sig_cap = strlen(argv[5]) / 2 + 1;
        uint8_t *sg = malloc(sig_cap);
        long nsg = unhex(argv[5], sg, sig_cap);
        if (nsg < 0) { printf("ERROR bad signature hex\n"); return 2; }
        if ((size_t)nsg != sig_len) {
            printf("ERROR signature length check failed: expected %zu bytes, got %ld\n",
                   sig_len, nsg);
            return 2;
        }
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;
        uint8_t *ctxbuf = NULL;
        if (argc >= 7) {
            ctxbuf = malloc(strlen(argv[6]) / 2 + 1);
            long nctx = unhex(argv[6], ctxbuf, strlen(argv[6]) / 2 + 1);
            if (nctx < 0) { printf("ERROR bad context hex\n"); return 2; }
            ctx = ctxbuf; ctx_len = (size_t)nctx;
        }
        OQS_STATUS st;
        if (ctx) st = OQS_SIG_verify_with_ctx_str(sig, msg, (size_t)nmsg, sg, sig_len, ctx, ctx_len, pk);
        else     st = OQS_SIG_verify(sig, msg, (size_t)nmsg, sg, sig_len, pk);
        printf("verify %s\n", st == OQS_SUCCESS ? "VALID" : "INVALID");
        return 0;
    }
    if (strcmp(cmd, "sig-bench") == 0) {
        int n = argc >= 4 ? atoi(argv[3]) : 100;
        if (n < 1) n = 1;
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        uint8_t *sg = malloc(sig_len);
        size_t sg_len = 0;
        const uint8_t msg[] = "benchmark message for signature throughput measurement";
        double *t = malloc(sizeof(double) * (size_t)n);
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { printf("ERROR keypair failed\n"); return 1; }
            t[i] = now_ms() - s;
        }
        printf("keygen_ms_median %.6f\n", median(t, (size_t)n));
        int ok = 0;
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            if (OQS_SIG_sign(sig, sg, &sg_len, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) {
                printf("ERROR sign failed\n"); return 1;
            }
            t[i] = now_ms() - s;
        }
        printf("sign_ms_median %.6f\n", median(t, (size_t)n));
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            OQS_STATUS st = OQS_SIG_verify(sig, msg, sizeof(msg) - 1, sg, sg_len, pk);
            t[i] = now_ms() - s;
            if (st == OQS_SUCCESS) ok++;
        }
        printf("verify_ms_median %.6f\n", median(t, (size_t)n));
        printf("verify_ok %d/%d\n", ok, n);
        printf("peak_rss_kb %ld\n", peak_rss_kb());
        return 0;
    }
    printf("ERROR unknown SIG command %s\n", cmd);
    return 2;
}
