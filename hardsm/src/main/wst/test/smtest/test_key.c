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


static void test_generate_key() {
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_generate_key(0, 0, out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("key: %s\n", out);
}

static void test_generate_keypair() {
    char public_key[1024] = {0};
    char private_key[1024] = {0};
    int public_key_len = sizeof(public_key);
    int private_key_len = sizeof(private_key);

    int error_code = ctx_generate_keypair(0, 0, public_key, public_key_len, private_key, private_key_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("public key: %s\n", public_key);
    printf("private key: %s\n", private_key);
}

void test_key() {
    test_generate_key();
    test_generate_keypair();
}
