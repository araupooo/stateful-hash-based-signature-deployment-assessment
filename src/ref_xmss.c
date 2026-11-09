/* ref_xmss.c — driver over the XMSS reference implementation
 * (xmss-reference, RFC 8391; bundled under src/xmss-reference/).
 *
 * Used only for cross-implementation agreement: verify liboqs XMSS
 * signatures under the reference implementation and vice versa, and
 * measure the reference implementation's throughput. The reference
 * implementation's key formats are [OID || root || PUB_SEED] for the
 * public key and [OID || idx || SK_SEED || SK_PRF || PUB_SEED || root
 * || BDS state] for the secret key (see xmss.h / params.h); the
 * signature bytes are the RFC 8391 wire format, identical to liboqs's
 * (liboqs XMSS signatures are 2500 bytes for SHA2_10_256, exactly the
 * RFC size, and its public key is the same 4-byte OID prefix plus the
 * 64-byte RFC public key).
 *
 * Usage:
 *   ref_xmss keygen <name>              (name e.g. XMSS-SHA2_10_256)
 *   ref_xmss sign <name> <sk-hex> <msg-hex>
 *   ref_xmss verify <name> <pk-hex> <msg-hex> <sig-hex>
 *   ref_xmss bench <name> <n-keygen> <n-sign> <n-verify>
 * Exit codes: 0 ok, 1 reference error, 2 driver input/length error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "xmss.h"
#include "params.h"

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

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: ref_xmss <cmd> <alg-name> [args...]\n");
        return 2;
    }
    const char *cmd = argv[1];
    const char *name = argv[2];
    uint32_t oid;
    if (xmss_str_to_oid(&oid, name) != 0) {
        printf("ERROR unknown XMSS parameter set %s\n", name);
        return 2;
    }
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        printf("ERROR cannot parse oid for %s\n", name);
        return 1;
    }
    size_t pk_len = XMSS_OID_LEN + params.pk_bytes;
    size_t sk_len = XMSS_OID_LEN + (size_t)params.sk_bytes;
    size_t sig_len = params.sig_bytes;

    if (strcmp(cmd, "info") == 0) {
        printf("type XMSS-REFERENCE\nlength_public_key %zu\nlength_secret_key %zu\n"
               "length_signature %zu\n",
               pk_len, sk_len, sig_len);
        return 0;
    }

    if (strcmp(cmd, "keygen") == 0) {
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        if (xmss_keypair(pk, sk, oid) != 0) {
            printf("ERROR keypair failed\n"); return 1;
        }
        print_hex("public_key", pk, pk_len);
        print_hex("secret_key", sk, sk_len);
        return 0;
    }

    if (strcmp(cmd, "sign") == 0) {
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
        uint8_t *sm = malloc(sig_len + (size_t)nmsg);
        unsigned long long smlen = 0;
        if (xmss_sign(sk, sm, &smlen, msg, (size_t)nmsg) != 0) {
            printf("ERROR sign failed\n"); return 1;
        }
        if (smlen != (unsigned long long)sig_len + (unsigned long long)nmsg) {
            printf("ERROR unexpected signed-message length %llu\n", smlen);
            return 1;
        }
        print_hex("signature", sm, sig_len);
        print_hex("secret_key", sk, sk_len);
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
        uint8_t *sg = malloc(sig_len);
        long nsg = unhex(argv[5], sg, sig_len);
        if (nsg != (long)sig_len) {
            printf("ERROR signature length check failed: expected %zu bytes, got %ld\n",
                   sig_len, nsg < 0 ? -1 : nsg);
            return 2;
        }
        /* xmss_sign_open expects [signature || message]. NOTE: the
         * reference implementation stages the message at offset
         * sig_bytes inside the output buffer (xmss_commons.c:
         * memcpy(m + params->sig_bytes, ...)), so mout must hold
         * sig_bytes + message bytes, not just the message. */
        uint8_t *sm = malloc(sig_len + (size_t)nmsg);
        memcpy(sm, sg, sig_len);
        memcpy(sm + sig_len, msg, (size_t)nmsg);
        uint8_t *mout = malloc(sig_len + (size_t)nmsg);
        unsigned long long mlen = 0;
        int rc = xmss_sign_open(mout, &mlen, sm, sig_len + (size_t)nmsg, pk);
        printf("verify %s\n", rc == 0 ? "VALID" : "INVALID");
        return 0;
    }

    if (strcmp(cmd, "bench") == 0) {
        int n_keygen = argc >= 4 ? atoi(argv[3]) : 3;
        int n_sign = argc >= 5 ? atoi(argv[4]) : 10;
        int n_verify = argc >= 6 ? atoi(argv[5]) : 10;
        if (n_keygen < 1) n_keygen = 1;
        if (n_sign < 1) n_sign = 1;
        if (n_verify < 1) n_verify = 1;
        const uint8_t msg[] = "benchmark message for xmss-reference throughput measurement";
        size_t mlen = sizeof(msg) - 1;
        int maxn = n_keygen > n_sign ? (n_keygen > n_verify ? n_keygen : n_verify)
                                     : (n_sign > n_verify ? n_sign : n_verify);
        double *t = malloc(sizeof(double) * (size_t)maxn);
        for (int i = 0; i < n_keygen; i++) {
            uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
            double s = now_ms();
            int rc = xmss_keypair(pk, sk, oid);
            t[i] = now_ms() - s;
            if (rc != 0) { printf("ERROR keypair failed\n"); return 1; }
            free(pk); free(sk);
        }
        printf("keygen_ms_median %.6f\n", median(t, (size_t)n_keygen));
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        if (xmss_keypair(pk, sk, oid) != 0) { printf("ERROR keypair failed\n"); return 1; }
        uint8_t *sm = malloc(sig_len + mlen);
        unsigned long long smlen = 0;
        int ok_sign = 0;
        for (int i = 0; i < n_sign; i++) {
            double s = now_ms();
            int rc = xmss_sign(sk, sm, &smlen, msg, mlen);
            t[i] = now_ms() - s;
            if (rc == 0) ok_sign++;
            else { printf("ERROR sign failed at %d\n", i); return 1; }
        }
        printf("sign_ms_median %.6f\n", median(t, (size_t)n_sign));
        printf("sign_ok %d/%d\n", ok_sign, n_sign);
        uint8_t *mout = malloc(sig_len + mlen);
        int ok = 0;
        for (int i = 0; i < n_verify; i++) {
            unsigned long long olen = 0;
            double s = now_ms();
            int rc = xmss_sign_open(mout, &olen, sm, smlen, pk);
            t[i] = now_ms() - s;
            if (rc == 0) ok++;
        }
        printf("verify_ms_median %.6f\n", median(t, (size_t)n_verify));
        printf("verify_ok %d/%d\n", ok, n_verify);
        printf("peak_rss_kb %ld\n", peak_rss_kb());
        return 0;
    }

    printf("ERROR unknown command %s\n", cmd);
    return 2;
}
