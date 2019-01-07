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


void test_device() {
    int error_code = YERR_SUCCESS;

    error_code = init_statistics();
    if (error_code != YERR_SUCCESS) print_error(error_code);




    char buf1[1024 * 32] = {0};
    DeviceStatuses device_statuses = ctx_get_device_statuses();
    printf("len: %d\n", device_statuses.count);
    print_device_statuses(&device_statuses, buf1);
    printf("%s\n", buf1);

    char buf2[1024 * 32] = {0};
    ctx_print_context(buf2, sizeof(buf2), true);
    printf("%s\n", buf2);
}
