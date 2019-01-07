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

    for (pipe_index = -100; pipe_index < 100; pipe_index++) {
        int error_code = ctx_digest(0, pipe_index, data, strlen(data), out, out_len);
        if (error_code != YERR_SUCCESS) print_error(error_code);
        printf("digest of data %s is %s\n", data, out);
    }
}

void test_device() {
    int error_code = YERR_SUCCESS;

    error_code = init();
    if (error_code != YERR_SUCCESS) print_error(error_code);

    int device_count = ctx_device_count();
    printf("device count: %d\n", device_count);

    int i;
    for (i = 0; i < device_count; i++) {
        error_code = ctx_open_device(i);
        if (error_code != YERR_SUCCESS) print_error(error_code);
    }

    error_code = ctx_open_pipe(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    error_code = ctx_login(0, "11111111");
    if (error_code != YERR_SUCCESS) print_error(error_code);


    test_digest();


    error_code = ctx_logout(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    error_code = ctx_close_all_pipe(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    char buf2[1024 * 32] = {0};
    DeviceStatuses device_statuses = ctx_get_device_statuses();
    printf("len: %d\n", device_statuses.count);
    print_device_statuses(&device_statuses, buf2);
    printf("%s\n", buf2);

    error_code = ctx_close_all_devices();
    if (error_code != YERR_SUCCESS) print_error(error_code);
}
