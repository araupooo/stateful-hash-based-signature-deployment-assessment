/* stfl_driver.c — minimal stdin/argv driver over liboqs 0.16.0 stateful
 * signatures (OQS_SIG_STFL API): LMS (RFC 8554) and XMSS (RFC 8391).
 *
 * liboqs exposes LMS/XMSS only through the separate stateful API, not
 * the generic OQS_SIG API, and only when built with
 * OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON (which
 * defines OQS_ALLOW_STFL_KEY_AND_SIG_GEN). The driver must be compiled
 * with -DOQS_ALLOW_STFL_KEY_AND_SIG_GEN so the OQS_SIG_STFL struct
 * layout (lengths, keypair/sign/verify function pointers) is visible.
 *
 * Secret keys are handled as liboqs serialized byte strings:
 * keygen prints the serialized secret key; sign takes a serialized
 * secret key, signs (advancing the one-time-signature index by one),
 * and prints the signature AND the updated serialized secret key, so
 * the caller can persist the new state. The leaf index used by the
 * signature (first 4 bytes, big-endian, per RFC 8554 section 5.4 /
 * RFC 8391 section 5.2) is printed, as are the remaining/total
 * signature counts. A signing caller that loses the updated secret
 * key reuses the same leaf index on the next signature — the failure
 * mode reproduced in remediation/reproduce_weakness.py.
 *
 * All inputs and outputs are hex on stdout, one labelled line each.
 * Length checks happen BEFORE calling liboqs. Exit codes: 0 ok,
 * 1 liboqs error, 2 driver input/length error.
 *
 * Usage:
 *   stfl_driver info <alg>
 *   stfl_driver keygen <alg>
 *   stfl_driver sign <alg> <sk-hex> <msg-hex>
 *   stfl_driver sign-many <alg> <sk-hex> <msg-hex> <n>
 *   stfl_driver verify <alg> <pk-hex> <msg-hex> <sig-hex>
 *   stfl_driver remaining <alg> <sk-hex>
 *   stfl_driver bench <alg> <n-keygen> <n-sign> <n-verify>
 *
 * Algorithm names are the liboqs identifiers, e.g. LMS_SHA256_H10_W4
 * and XMSS-SHA2_10_256.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>
#include <oqs/sig_stfl.h>

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

/* Peak RSS in kilobytes, read from /proc/self/status VmHWM (see
 * pq_driver.c for why getrusage ru_maxrss is not used here). */
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

/* Leaf index of a signature: XMSS (RFC 8391 section 5.2) carries idx
 * in the first 4 bytes; the liboqs/HSS LMS signature carries the
 * leaf index q at byte offset 4, after a 4-byte HSS framing prefix
 * (verified: first signature of a fresh LMS key has bytes 0-3 = 0,
 * bytes 4-7 = 0, bytes 8-11 = LM-OTS typecode 0x00000003 for W4). */
static uint32_t leaf_index(const char *alg, const uint8_t *sig) {
    size_t off = (strncmp(alg, "LMS_", 4) == 0) ? 4 : 0;
    return ((uint32_t)sig[off] << 24) | ((uint32_t)sig[off + 1] << 16) |
           ((uint32_t)sig[off + 2] << 8) | (uint32_t)sig[off + 3];
}

/* Serialize a secret-key object; caller frees with OQS_MEM_secure_free. */
static OQS_STATUS serialize_sk(OQS_SIG_STFL_SECRET_KEY *sk, uint8_t **buf, size_t *len) {
    return sk->serialize_key(buf, len, sk);
}

/* Secure-store callback: liboqs refuses to sign a stateful key unless
 * one is registered (see sig_stfl_lms_functions.c: signing without a
 * store callback is an error, and a failed store wipes the signature).
 * This driver captures the serialized updated key the library hands
 * back after a successful signature, so the caller can persist it;
 * the driver itself writes nothing to disk. */
static uint8_t *g_store_buf = NULL;
static size_t g_store_len = 0;

static OQS_STATUS store_cb(uint8_t *sk_buf, size_t buf_len, void *context) {
    (void)context;
    if (sk_buf == NULL || buf_len == 0) return OQS_ERROR;
    free(g_store_buf);
    g_store_buf = malloc(buf_len);
    if (!g_store_buf) return OQS_ERROR;
    memcpy(g_store_buf, sk_buf, buf_len);
    g_store_len = buf_len;
    return OQS_SUCCESS;
}

static void set_store_cb(OQS_SIG_STFL_SECRET_KEY *sk) {
    /* NOTE: liboqs's LMS setter ignores the call when context is NULL
     * (OQS_SECRET_KEY_LMS_set_store_cb requires sk && store_cb &&
     * context), so a non-NULL context is mandatory — passing NULL
     * silently leaves signing disabled. */
    static int store_context = 0;
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, store_cb, &store_context);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: stfl_driver <cmd> <alg> [args...]\n");
        return 2;
    }
    const char *cmd = argv[1];
    const char *alg = argv[2];

    OQS_init();
    if (OQS_SIG_STFL_keygen_and_sign_supported() != 1) {
        printf("ERROR stateful keygen/sign not enabled in this liboqs build\n");
        return 1;
    }
    OQS_SIG_STFL *sig = OQS_SIG_STFL_new(alg);
    if (!sig) {
        printf("ERROR algorithm not enabled %s\n", alg);
        return 1;
    }
    size_t pk_len = sig->length_public_key, sk_len = sig->length_secret_key;
    size_t sig_len = sig->length_signature;

    if (strcmp(cmd, "info") == 0) {
        printf("type SIG_STFL\nlength_public_key %zu\nlength_secret_key %zu\n"
               "length_signature %zu\n",
               pk_len, sk_len, sig_len);
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    if (strcmp(cmd, "keygen") == 0) {
        OQS_SIG_STFL_SECRET_KEY *sk = OQS_SIG_STFL_SECRET_KEY_new(alg);
        if (!sk) { printf("ERROR secret key object creation failed\n"); return 1; }
        uint8_t *pk = malloc(pk_len);
        if (OQS_SIG_STFL_keypair(sig, pk, sk) != OQS_SUCCESS) {
            printf("ERROR keypair failed\n"); return 1;
        }
        uint8_t *skbuf = NULL;
        size_t skbuflen = 0;
        if (serialize_sk(sk, &skbuf, &skbuflen) != OQS_SUCCESS) {
            printf("ERROR serialize secret key failed\n"); return 1;
        }
        unsigned long long remain = 0, total = 0;
        OQS_SIG_STFL_sigs_remaining(sig, &remain, sk);
        OQS_SIG_STFL_sigs_total(sig, &total, sk);
        print_hex("public_key", pk, pk_len);
        print_hex("secret_key", skbuf, skbuflen);
        printf("secret_key_serialized_len %zu\n", skbuflen);
        printf("sigs_remaining %llu\nsigs_total %llu\n", remain, total);
        OQS_MEM_secure_free(skbuf, skbuflen);
        OQS_SIG_STFL_SECRET_KEY_free(sk);
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    if (strcmp(cmd, "sign") == 0 || strcmp(cmd, "sign-many") == 0) {
        if (argc < 5) { printf("ERROR missing secret key or message\n"); return 2; }
        int count = 1;
        if (strcmp(cmd, "sign-many") == 0) {
            if (argc < 6) { printf("ERROR missing count\n"); return 2; }
            count = atoi(argv[5]);
            if (count < 1) count = 1;
        }
        size_t sk_cap = strlen(argv[3]) / 2 + 1;
        uint8_t *skbuf = malloc(sk_cap);
        long nsk = unhex(argv[3], skbuf, sk_cap);
        if (nsk < 0) { printf("ERROR bad secret key hex\n"); return 2; }
        OQS_SIG_STFL_SECRET_KEY *sk = OQS_SIG_STFL_SECRET_KEY_new(alg);
        if (!sk) { printf("ERROR secret key object creation failed\n"); return 1; }
        if (sk->deserialize_key(sk, skbuf, (size_t)nsk, NULL) != OQS_SUCCESS) {
            printf("ERROR deserialize secret key failed\n"); return 1;
        }
        set_store_cb(sk);
        size_t msg_cap = strlen(argv[4]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[4], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        uint8_t *sg = malloc(sig_len);
        for (int i = 0; i < count; i++) {
            size_t sg_len = 0;
            OQS_STATUS st = OQS_SIG_STFL_sign(sig, sg, &sg_len, msg, (size_t)nmsg, sk);
            if (st != OQS_SUCCESS) {
                printf("sign_failed_at %d\n", i);
                printf("ERROR sign failed status %d (key exhausted or invalid state)\n", (int)st);
                return 1;
            }
            unsigned long long remain = 0;
            OQS_SIG_STFL_sigs_remaining(sig, &remain, sk);
            printf("signature_index %u\n", leaf_index(alg, sg));
            printf("sigs_remaining %llu\n", remain);
            print_hex("signature", sg, sg_len);
        }
        uint8_t *skbuf2 = NULL;
        size_t skbuflen2 = 0;
        if (serialize_sk(sk, &skbuf2, &skbuflen2) != OQS_SUCCESS) {
            printf("ERROR serialize updated secret key failed\n"); return 1;
        }
        /* The store callback must have received exactly the serialized
         * key the library produced after signing; report a mismatch
         * rather than silently printing a different state. */
        if (g_store_len != skbuflen2 || memcmp(g_store_buf, skbuf2, skbuflen2) != 0) {
            printf("ERROR store callback state mismatch\n"); return 1;
        }
        print_hex("secret_key", skbuf2, skbuflen2);
        printf("secret_key_serialized_len %zu\n", skbuflen2);
        OQS_MEM_secure_free(skbuf2, skbuflen2);
        OQS_SIG_STFL_SECRET_KEY_free(sk);
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    if (strcmp(cmd, "verify") == 0) {
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
        size_t sig_cap = strlen(argv[5]) / 2 + 1;
        uint8_t *sg = malloc(sig_cap);
        long nsg = unhex(argv[5], sg, sig_cap);
        if (nsg < 0) { printf("ERROR bad signature hex\n"); return 2; }
        if ((size_t)nsg != sig_len) {
            printf("ERROR signature length check failed: expected %zu bytes, got %ld\n",
                   sig_len, nsg);
            return 2;
        }
        OQS_STATUS st = OQS_SIG_STFL_verify(sig, msg, (size_t)nmsg, sg, sig_len, pk);
        printf("verify %s\n", st == OQS_SUCCESS ? "VALID" : "INVALID");
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    if (strcmp(cmd, "remaining") == 0) {
        if (argc < 4) { printf("ERROR missing secret key\n"); return 2; }
        size_t sk_cap = strlen(argv[3]) / 2 + 1;
        uint8_t *skbuf = malloc(sk_cap);
        long nsk = unhex(argv[3], skbuf, sk_cap);
        if (nsk < 0) { printf("ERROR bad secret key hex\n"); return 2; }
        OQS_SIG_STFL_SECRET_KEY *sk = OQS_SIG_STFL_SECRET_KEY_new(alg);
        if (!sk) { printf("ERROR secret key object creation failed\n"); return 1; }
        if (sk->deserialize_key(sk, skbuf, (size_t)nsk, NULL) != OQS_SUCCESS) {
            printf("ERROR deserialize secret key failed\n"); return 1;
        }
        unsigned long long remain = 0, total = 0;
        OQS_SIG_STFL_sigs_remaining(sig, &remain, sk);
        OQS_SIG_STFL_sigs_total(sig, &total, sk);
        printf("sigs_remaining %llu\nsigs_total %llu\n", remain, total);
        OQS_SIG_STFL_SECRET_KEY_free(sk);
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    if (strcmp(cmd, "bench") == 0) {
        int n_keygen = argc >= 4 ? atoi(argv[3]) : 10;
        int n_sign = argc >= 5 ? atoi(argv[4]) : 20;
        int n_verify = argc >= 6 ? atoi(argv[5]) : 20;
        if (n_keygen < 1) n_keygen = 1;
        if (n_sign < 1) n_sign = 1;
        if (n_verify < 1) n_verify = 1;
        const uint8_t msg[] = "benchmark message for stateful signature throughput measurement";
        double *t = malloc(sizeof(double) * (size_t)(n_keygen > n_sign ? (n_keygen > n_verify ? n_keygen : n_verify) : (n_sign > n_verify ? n_sign : n_verify)));
        /* keygen */
        for (int i = 0; i < n_keygen; i++) {
            OQS_SIG_STFL_SECRET_KEY *sk = OQS_SIG_STFL_SECRET_KEY_new(alg);
            uint8_t *pk = malloc(pk_len);
            double s = now_ms();
            OQS_STATUS st = OQS_SIG_STFL_keypair(sig, pk, sk);
            t[i] = now_ms() - s;
            if (st != OQS_SUCCESS) { printf("ERROR keypair failed\n"); return 1; }
            OQS_SIG_STFL_SECRET_KEY_free(sk);
            free(pk);
        }
        printf("keygen_ms_median %.6f\n", median(t, (size_t)n_keygen));
        /* sign: one keypair, n_sign sequential signatures (state advances) */
        OQS_SIG_STFL_SECRET_KEY *sk = OQS_SIG_STFL_SECRET_KEY_new(alg);
        uint8_t *pk = malloc(pk_len);
        uint8_t *sg = malloc(sig_len);
        size_t sg_len = 0;
        if (OQS_SIG_STFL_keypair(sig, pk, sk) != OQS_SUCCESS) { printf("ERROR keypair failed\n"); return 1; }
        set_store_cb(sk);
        int ok_sign = 0;
        for (int i = 0; i < n_sign; i++) {
            double s = now_ms();
            OQS_STATUS st = OQS_SIG_STFL_sign(sig, sg, &sg_len, msg, sizeof(msg) - 1, sk);
            t[i] = now_ms() - s;
            if (st == OQS_SUCCESS) ok_sign++;
            else { printf("ERROR sign failed at %d\n", i); return 1; }
        }
        printf("sign_ms_median %.6f\n", median(t, (size_t)n_sign));
        printf("sign_ok %d/%d\n", ok_sign, n_sign);
        /* verify: reuse the last signature */
        int ok = 0;
        for (int i = 0; i < n_verify; i++) {
            double s = now_ms();
            OQS_STATUS st = OQS_SIG_STFL_verify(sig, msg, sizeof(msg) - 1, sg, sg_len, pk);
            t[i] = now_ms() - s;
            if (st == OQS_SUCCESS) ok++;
        }
        printf("verify_ms_median %.6f\n", median(t, (size_t)n_verify));
        printf("verify_ok %d/%d\n", ok, n_verify);
        printf("peak_rss_kb %ld\n", peak_rss_kb());
        OQS_SIG_STFL_SECRET_KEY_free(sk);
        OQS_SIG_STFL_free(sig);
        OQS_destroy();
        return 0;
    }

    printf("ERROR unknown STFL command %s\n", cmd);
    return 2;
}
