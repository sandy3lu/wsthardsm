#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/sm_api.h"
#include "../../include/util.h"
#include "../../include/device.h"


void test_device() {
    init_context();
    char buf[4] = {0};
    print_context(buf, sizeof(buf), true);
    printf("%s", buf);
}
