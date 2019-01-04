#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/sm_api.h"
#include "../../include/util.h"
#include "../../include/context.h"
#include "../../include/device.h"


void test_device() {
    int error_code = YERR_SUCCESS;

    error_code = init_context();
    if (error_code != YERR_SUCCESS) print_error(error_code);

    char buf[1024 * 32] = {0};
    print_context(buf, sizeof(buf), true);
    printf("%s\n", buf);

    error_code = finalize_context();
    if (error_code != YERR_SUCCESS) print_error(error_code);
}
