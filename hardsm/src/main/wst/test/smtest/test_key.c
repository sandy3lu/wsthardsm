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
    int pipe_index = 0;
    char out[1024] = {0};
    int out_len = sizeof(out);

    int error_code = ctx_generate_key(0, pipe_index, true, out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("key: %s\n", out);

    error_code = ctx_generate_key(0, pipe_index, false, out, out_len);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    printf("key: %s\n", out);
}


void test_key() {
    test_generate_key();
}
