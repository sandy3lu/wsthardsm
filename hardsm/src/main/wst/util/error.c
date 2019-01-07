#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"


static char* MSGS[1024] = {0};


void init_error_string() {
    MSGS[YERR_SUCCESS] = "success";
    MSGS[YERR_FORMAT_ERROR] = "data format error";
    MSGS[NO_DEVICE_ERROR] = "no device error";
    MSGS[INDEX_OUTOF_BOUND] = "index out of bound";
    MSGS[DEVICE_NOT_OPENED] = "device not opened";
    MSGS[PIPE_NOT_OPENED] = "pipe not opened";
    MSGS[PIPE_RESOURCE_EXCEEDED] = "pipe resource exceeded";
}

char *get_error_string(int code) {
    if (code > 0 && code < 300) {
        return SM_GetErrorString(code, false);
    } else {
      return MSGS[code];
    }
}

void print_error(int code) {
    const char *msg = get_error_string(code);
    fprintf(stderr, "code: %d\n", code);
    fprintf(stderr, "msg: %s\n", msg);
}
