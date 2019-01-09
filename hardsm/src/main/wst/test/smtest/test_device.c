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
#include "smtest.h"


void test_device() {
    int error_code = YERR_SUCCESS;

    error_code = init();
    if (error_code != YERR_SUCCESS) print_error(error_code);

    int device_count = ctx_device_count();
    printf("device count: %d\n", device_count);


    error_code = ctx_open_device(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_open_device(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_open_pipes(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    error_code = ctx_login(0, "11111111");
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_login(0, "11111111");
    if (error_code != YERR_SUCCESS) print_error(error_code);


    test_crypto();
    test_key();


    error_code = ctx_logout(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    error_code = ctx_close_all_pipe(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);

    char buf1[1024 * 32] = {0};
    DeviceStatuses device_statuses = ctx_get_device_statuses();
    printf("len: %d\n", device_statuses.count);
    print_device_statuses(&device_statuses, buf1);
    printf("%s\n", buf1);

    error_code = ctx_close_all_devices();
    if (error_code != YERR_SUCCESS) print_error(error_code);
}
