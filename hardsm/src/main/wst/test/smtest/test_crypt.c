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


static void test_digest() {
    int pipe_index = 0;
    const char *data = "abc";
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_digest(0, pipe_index, data, strlen(data), out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("digest of data %s is %s\n", data, out);
}

static void test_digest_section() {
    int pipe_index = 0;
    const char *data = "0123456701234567012345670123456701234567012345670123456701234567";
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_digest_init(0, pipe_index);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, pipe_index, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, pipe_index, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_update(0, pipe_index, data, strlen(data));
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_digest_final(0, pipe_index, data, strlen(data), out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    printf("digest of data %s is %s\n", data, out);
}

static void test_random() {
    char out[1024] = {0};
    int out_len;

    for (out_len = 0; out_len < 20; out_len++) {
        int error_code = ctx_random(0, 0, out, out_len);
        if (error_code != YERR_SUCCESS) print_error(error_code);
        else printf("random: %s\n", out);
    }
}

void test_crypto() {
    test_digest();
    test_digest_section();
    test_random();
}
