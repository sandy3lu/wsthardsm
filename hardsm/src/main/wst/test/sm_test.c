#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../include/util.h"
#include "../include/sm.h"

static int g_errors = 0;
static int g_silent = 0;


static void test_device_init(const char *password) {
    Result result = device_init(password);
    result = handle_result(result);

    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s\n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "OK\n");
    }
}


static void test_device_finalize() {
    Result result = device_finalize();
    result = handle_result(result);

    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s\n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "OK\n");
    }
}


static void print_cert(const char *b64_cert) {
    MinimalCert cert_out;
    memset(&cert_out, 0, sizeof(MinimalCert));
    Result result = load_cert(b64_cert, &cert_out);
    result = handle_result(result);
    if (result.code != YERR_SUCCESS) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed load cert: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "cert: %s\n", b64_cert);
        fprintf(stderr, "vs: %s\n", cert_out.vs);
        fprintf(stderr, "pk: %s\n", cert_out.pk);
        fprintf(stderr, "pd: %s\n", cert_out.pd);
        fprintf(stderr, "sg: %s\n", cert_out.da);
        fprintf(stderr, "sd: %s\n", cert_out.sd);
        fprintf(stderr, "ed: %s\n", cert_out.ed);
        fprintf(stderr, "lv: %s\n", cert_out.lv);
        fprintf(stderr, "ts: %s\n", cert_out.ts);
        fprintf(stderr, "mf: %s\n", cert_out.mf);
        fprintf(stderr, "ag: %s\n", cert_out.ag);
        fprintf(stderr, "bt: %s\n", cert_out.bt);
        fprintf(stderr, "fg: %s\n", cert_out.fg);
        fprintf(stderr, "cn: %s\n", cert_out.cn);
        fprintf(stderr, "iu: %s\n", cert_out.iu);
        fprintf(stderr, "sc: %s\n", cert_out.sc);
        fprintf(stderr, "sn: %s\n", cert_out.sn);
        fprintf(stderr, "st: %s\n", cert_out.st);
        fprintf(stderr, "un: %s\n", cert_out.un);
        fprintf(stderr, "id: %s\n", cert_out.id);
        fprintf(stderr, "sg: %s\n", cert_out.sg);
    }
}


static void test_cert(const char *hex_private, const char *hex_public) {
    MinimalCert minimal_cert;
    memset(&minimal_cert, 0, sizeof(MinimalCert));
    strcpy(minimal_cert.vs, "01");
    strcpy(minimal_cert.pk, "ac4fa6307e09d80b2c7cd179113c9e45203a07372a600c550c"
                            "76dbf6231789dc80604baf5e270ed8f6113cf221188a8da4b2"
                            "70b8047714c46975b8389a13d342");
    strcpy(minimal_cert.pd, "pd");
    strcpy(minimal_cert.da, "da");
    strcpy(minimal_cert.sg, "sg");
    strcpy(minimal_cert.sd, "20180606");
    strcpy(minimal_cert.ed, "20202010");
    strcpy(minimal_cert.lv, "02");
    strcpy(minimal_cert.ts, "2018:07:07");
    strcpy(minimal_cert.mf, "wst");
    strcpy(minimal_cert.ag, "ag");
    strcpy(minimal_cert.bt, "bt");
    strcpy(minimal_cert.fg, "fg");
    strcpy(minimal_cert.cn, "CN");
    strcpy(minimal_cert.iu, "yunjingit");
    strcpy(minimal_cert.sc, "201806210000000001");
    strcpy(minimal_cert.sn, "yunjing_sample_seal");
    strcpy(minimal_cert.st, "INVOICE");
    strcpy(minimal_cert.un, "use_unit_name");
    strcpy(minimal_cert.id, "201806210000000001");

    char b64_cert[MAX_CERT_LEN + 1] = {0};
    Result result = sign_cert(&minimal_cert, hex_private, b64_cert);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if(g_silent) {
            fprintf(stderr, "failed sign cert: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s\n", result.msg);
        }
        return;
    } else {
        print_cert(b64_cert);
    }

    int verify_result = 0;
    result = verify_cert(b64_cert, hex_public, &verify_result);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed verify cert: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    } else {
        fprintf(stderr, "verify result: %d\n", verify_result);
    }

    MinimalCert cert_out;
    memset(&cert_out, 0, sizeof(MinimalCert));
    result = load_cert(b64_cert, &cert_out);
    result = handle_result(result);
    if (result.code != YERR_SUCCESS) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed load cert: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }

    if (g_silent) {
        fprintf(stderr, "OK\n");
    }
}


static void test_generate_ecc_key(char *hex_public, int hex_public_len,
                                  char *hex_private, int hex_private_len) {
    const char *start_date = "20180601";
    const char *end_date = "20201010";
    Result result = generate_ecc_key(start_date, end_date, hex_public,
                                     hex_public_len, hex_private,
                                     hex_private_len);
    result = handle_result(result);

    if (result.code != YERR_SUCCESS) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed generate key pair: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "OK\n");
    }
}


static void test_sm3_hash_data() {
    const char *data = "this is data";
    char out[128 + 1] = {0};
    int out_len = sizeof(out);
    char hex_hash[128 + 1] = {0};

    Result result = sm3_hash_data(data, strlen(data), out, &out_len);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed hash data: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }

    to_hex(hex_hash, sizeof(hex_hash), out, out_len);
    if (g_silent) {
        fprintf(stderr, "hex digest: %s\n", hex_hash);
        fprintf(stderr, "OK\n");
    }
}


static void print_signature(const char *b64_signature) {
    Signature signature;
    memset(&signature, 0, sizeof(signature));

    Result result = load_signature(b64_signature, &signature);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed load signature: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "signature: %s\n", b64_signature);
        fprintf(stderr, "vs: %s\n", signature.vs);
        fprintf(stderr, "dh: %s\n", signature.dh);
        fprintf(stderr, "cs: %s\n", signature.cs);
        fprintf(stderr, "ts: %s\n", signature.ts);
        fprintf(stderr, "mc: %s\n", signature.mc);
        fprintf(stderr, "ct: %s\n", signature.ct);
        fprintf(stderr, "sg: %s\n", signature.sg);
    }
}


static void test_sign_signature(const char *hex_private, char *b64_signature) {
    Signature signature;
    memset(&signature, 0, sizeof(signature));
    strcpy(signature.vs, "01");
    strcpy(signature.dh, "1b1b699f0bcf806ee858b82e5298e27c"
                         "138816a2d0acc3d8c376e2546016e942");
    strcpy(signature.ts, "2018:06:02");
    strcpy(signature.mc, "0001-0001-0000-0001");
    strcpy(signature.ct, "1d6498296c98783fe950998c1f6dadc2494f341aeb08c22b1b262"
                         "c023aa662c91468c6580cf003ef5e8903f5f59dd6263fd06b8dd7"
                         "0872b794207a7592cd2425");

    Result result = sign_signature(&signature, hex_private, b64_signature);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed hash data: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }
    print_signature(b64_signature);
}


static void test_verify_signature(const char *hex_public,
                                  const char *b64_signature) {
    int verify_result = 0;
    Result result = verify_signature(b64_signature, hex_public, &verify_result);
    result = handle_result(result);
    if (YERR_SUCCESS != result.code) {
        g_errors++;
        if (g_silent) {
            fprintf(stderr, "failed verify: \n");
            fprintf(stderr, "code: %d\n", result.code);
            fprintf(stderr, "msg: %s: \n", result.msg);
        }
        return;
    }
    if (g_silent) {
        fprintf(stderr, "verify result: %d\n", verify_result);
        fprintf(stderr, "OK\n");
    }
}


/* sm password
 * sm password sign 1000
 * sm password verify 1000
 */
int main(int argc, char **argv) {
    if (argc != 4 && argc != 2) {
        fprintf(stderr, "params error\n");
        fprintf(stderr, "sm password [sign/verify] [loops]\n");
        return 0;
    }

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "test device init\n");
    test_device_init(argv[1]);

    if (argc == 2) {
        g_silent = 1;
        if (g_silent) {
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test generate key pairs\n");
        }
        char hex_public[1024] = {0};
        char hex_private[1024] = {0};
        test_generate_ecc_key(hex_public, sizeof(hex_public),
                              hex_private, sizeof(hex_private));
        if (g_silent) {
            fprintf(stderr, "private key: %s\n", hex_private);
            fprintf(stderr, "public key: %s\n", hex_public);
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test cert\n");
        }
        test_cert(hex_private, hex_public);
        if (g_silent) {
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test sm3 hash data\n");
        }
        test_sm3_hash_data();
        if (g_silent) {
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test signature\n");
        }
        char b64_signature[MAX_SIGNATURE_LEN + 1] = {0};
        if (g_silent) {
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test sign signature\n");
        }
        test_sign_signature(hex_private, b64_signature);
        if (g_silent) {
            fprintf(stderr, "========================================\n");
            fprintf(stderr, "test verify signature\n");
        }
        test_verify_signature(hex_public, b64_signature);
    } else {
        g_silent = 0;
        char hex_public[1024] = {0};
        char hex_private[1024] = {0};
        test_generate_ecc_key(hex_public, sizeof(hex_public),
                               hex_private, sizeof(hex_private));
        char b64_signature[MAX_SIGNATURE_LEN + 1] = {0};
        int loop = atoi(argv[3]);
        int issign = true;
        if (0 == strcmp("sign", argv[2])) {
            issign = true;
        } else if (0 == strcmp("verify", argv[2])) {
            issign = false;
        }


        struct timeval timer_usec;
        long long start_time; /* timestamp in microsecond */
        long long end_time; /* timestamp in microsecond */
        gettimeofday(&timer_usec, NULL);
        start_time = timer_usec.tv_sec * 1000000 +
                     (long long) timer_usec.tv_usec;

        int i;
        for (i = 0; i < loop; i++) {
            if (issign) {
                test_sign_signature(hex_private, b64_signature);
            } else {
                test_verify_signature(hex_public, b64_signature);
            }
        }

        gettimeofday(&timer_usec, NULL);
        end_time = timer_usec.tv_sec * 1000000 + (long long) timer_usec.tv_usec;
        fprintf(stderr, "time spent: %f\n", (end_time-start_time) / 1000000.0);
        fprintf(stderr, "time loops: %d\n", loop);
        fprintf(stderr, "loop times per second: %f\n",
                1.0 * loop / (end_time - start_time) * 1000000.0);
    }

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "test finalize\n");

    test_device_finalize();
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "total errors: %d\n", g_errors);
    return 0;
}
