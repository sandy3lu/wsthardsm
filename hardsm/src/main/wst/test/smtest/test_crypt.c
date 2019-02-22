#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/sm_api.h"
#include "../../include/util.h"
#include "../../include/data.h"
#include "../../include/device.h"
#include "../../include/context.h"


static const char *origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
static const char *encrypt_result = "eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a2921bda5859da7534a80121a1e79b859431";


static long current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long milliseconds = te.tv_sec * 1000L + te.tv_usec / 1000; // calculate milliseconds
    return milliseconds;
}

static void test_digest() {
    const char *data = "abc";
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_digest(0, 0, data, strlen(data), out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("digest of data %s is %s\n", data, out);
}

static void test_digest_section() {
    const char *data = "0123456701234567012345670123456701234567012345670123456701234567";
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_digest_init(0, 0);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, 0, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, 0, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, 0, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_final(0, 0, data, strlen(data), out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    printf("digest of data %s is %s\n", data, out);
}

static void test_random() {
    char out[1024] = {0};
    int out_len = 32;

    int error_code = ctx_random(0, 0, out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    else printf("random: %s\n", out);
}

static void test_encrypt() {
    const char *data = origin_data;
    const char *hex_iv = NULL;
    const char *hex_secret_key = "9353b0995d93c0b7f470deec26112172";
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_encrypt(0, 0, hex_secret_key, hex_iv, data, strlen(data), out, &out_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
    } else {
        char hex_out[1024] = {0};
        to_hex(hex_out, sizeof(hex_out), out, out_len);
        if (0 != strcmp(hex_out, encrypt_result)) {
            printf("encrypt error\n");
        } else {
            printf("encrypt success\n");
        }
    }
}

static void test_decrypt() {
    const char *hex_data = encrypt_result;
    const char *hex_iv = NULL;
    const char *hex_secret_key = "9353b0995d93c0b7f470deec26112172";
    char data[1024] = {0};
    int data_len = sizeof(data);
    char out[1024] = {0};
    int out_len = sizeof(out);

    from_hex(data, &data_len, hex_data);

    int error_code = ctx_decrypt(0, 0, hex_secret_key, hex_iv, data, data_len, out, &out_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
    } else {
        if (0 != strcmp(origin_data, out)) {
            printf("decrypt error\n");
        } else {
            printf("decrypt success\n");
        }
    }
}

static void test_section_encrypt() {
    const char *data = origin_data;
    const char *hex_iv = NULL;
    const char *hex_secret_key = "9353b0995d93c0b7f470deec26112172";
    char out[1024] = {0};
    int out_len = 0;

    int error_code = ctx_encrypt_init(0, 0, hex_secret_key, hex_iv);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    const char *cursor = data;
    char *out_cursor = out;
    int out_cursor_len = 0;
    while (cursor + 16 < data + strlen(data)) {
        out_cursor_len = 16;
        error_code = ctx_encrypt_update(0, 0, cursor, 16, out_cursor, &out_cursor_len);
        if (error_code != YERR_SUCCESS) {
            print_error(error_code);
            return;
        }
        cursor += 16;
        out_cursor += out_cursor_len;
        out_len += out_cursor_len;
    }
    out_cursor_len = 128;
    error_code = ctx_encrypt_final(0, 0, cursor, strlen(cursor), out_cursor, &out_cursor_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }
    out_cursor += out_cursor_len;
    out_len += out_cursor_len;

    char hex_out[1024] = {0};
    to_hex(hex_out, sizeof(hex_out), out, out_len);
    if (0 != strcmp(hex_out, encrypt_result)) {
        printf("encrypt error\n");
    } else {
        printf("encrypt success\n");
    }
}

static void test_section_decrypt() {
    const char *hex_data = encrypt_result;
    const char *hex_iv = NULL;
    const char *hex_secret_key = "9353b0995d93c0b7f470deec26112172";
    char data[1024] = {0};
    int data_len = sizeof(data);
    char out[1024] = {0};
    int out_len = 0;

    from_hex(data, &data_len, hex_data);

    int error_code = ctx_decrypt_init(0, 0, hex_secret_key, hex_iv);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    const char *cursor = data;
    char *out_cursor = out;
    int out_cursor_len = 0;
    while (cursor + 16 < data + data_len) {
        out_cursor_len = 16;
        error_code = ctx_decrypt_update(0, 0, cursor, 16, out_cursor, &out_cursor_len);
        if (error_code != YERR_SUCCESS) {
            print_error(error_code);
            return;
        }
        cursor += 16;
        out_cursor += out_cursor_len;
        out_len += out_cursor_len;
    }
    out_cursor_len = 128;
    error_code = ctx_decrypt_final(0, 0, cursor, strlen(cursor), out_cursor, &out_cursor_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }
    out_cursor += out_cursor_len;
    out_len += out_cursor_len;

    if (0 != strcmp(out, origin_data)) {
        printf("decrypt error\n");
    } else {
        printf("decrypt success\n");
    }
}

static void test_sign_verify() {
    const char *data = origin_data;

    char public_key[1024] = {0};
    char private_key[1024] = {0};
    int public_key_len = sizeof(public_key);
    int private_key_len = sizeof(private_key);
    char signature[256] = {0};
    int signature_len = sizeof(signature);

    int error_code = ctx_generate_keypair(0, 0, public_key, public_key_len, private_key, private_key_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    error_code = ctx_ecc_sign(0, 0, private_key, data, signature, signature_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    int verify_result = 0;
    error_code = ctx_ecc_verify(0, 0, public_key, &verify_result, data, signature);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    if (0 != verify_result) {
        print_error(verify_result);
    }
}

static void test_digest_alot() {
    int errors = 0;
    int counts = 10000;

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < counts; i++) {
        const char *data = "abc";
        char out[1024] = {0};
        int out_len = sizeof(out);
        int error_code = ctx_digest(0, 0, data, strlen(data), out, out_len);
        if (error_code != YERR_SUCCESS) errors++;
    }

    long stop_timestamp = current_timestamp();

    printf("digest performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void test_sign_alot() {
    const char *data = origin_data;
    int errors = 0;
    int counts = 10000;

    char public_key[1024] = {0};
    char private_key[1024] = {0};
    int public_key_len = sizeof(public_key);
    int private_key_len = sizeof(private_key);
    char signature[256] = {0};
    int signature_len = sizeof(signature);

    int error_code = ctx_generate_keypair(0, 0, public_key, public_key_len, private_key, private_key_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < counts; i++) {
        error_code = ctx_ecc_sign(0, 0, private_key, data, signature, signature_len);
        if (error_code != YERR_SUCCESS) errors++;
    }

    long stop_timestamp = current_timestamp();

    printf("sign performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void test_verify_alot() {
    const char *data = origin_data;
    int errors = 0;
    int counts = 10000;

    char public_key[1024] = {0};
    char private_key[1024] = {0};
    int public_key_len = sizeof(public_key);
    int private_key_len = sizeof(private_key);
    char signature[256] = {0};
    int signature_len = sizeof(signature);

    int error_code = ctx_generate_keypair(0, 0, public_key, public_key_len, private_key, private_key_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    error_code = ctx_ecc_sign(0, 0, private_key, data, signature, signature_len);
    if (error_code != YERR_SUCCESS) {
        print_error(error_code);
        return;
    }

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < counts; i++) {
        int verify_result = 0;
        error_code = ctx_ecc_verify(0, 0, public_key, &verify_result, data, signature);
        if (error_code != YERR_SUCCESS || 0 != verify_result) errors++;
    }

    long stop_timestamp = current_timestamp();

    printf("sign performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

void test_crypto() {
    test_digest();
    test_digest_section();
    test_random();
    test_encrypt();
    test_decrypt();
    test_section_encrypt();
    test_section_decrypt();
    test_sign_verify();

    test_digest_alot();
    test_sign_alot();
    test_verify_alot();
}
