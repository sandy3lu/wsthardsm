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

    error_code = ctx_open_device(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_open_pipes(0,2);//ctx_open_all_pipes(0);
    if (error_code != YERR_SUCCESS) print_error(error_code);
    error_code = ctx_login(0, "11111111");
    if (error_code != YERR_SUCCESS) print_error(error_code);


    test_crypto();
    test_key();


    error_code = final();
    if (error_code != YERR_SUCCESS) print_error(error_code);
}
