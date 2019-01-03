#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/util.h"
#include "../../include/device.h"


static void test_count_device() {
    int device_count = 0;
    int error = get_device_count(&device_count);
    if (error != YERR_SUCCESS) {
        print_error(error);
    }

    printf("device count: %d\n", device_count);
}


void test_device() {
    test_count_device();
}
