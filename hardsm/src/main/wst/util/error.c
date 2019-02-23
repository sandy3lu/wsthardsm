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
    MSGS[BUFSIZE_TOO_SMALL] = "buf size too small";
    MSGS[NEED_LOGIN] = "need login";
    MSGS[RANDOM_LEN_OUTOF_BOUND] = "random length out of bound";
    MSGS[KEY_LENGTH_INVALID] = "key length invalid";
    MSGS[IV_LENGTH_INVALID] = "iv length invalid";
    MSGS[BLOCK_LENGTH_INVALID] = "block length invalid";
    MSGS[DATA_TOO_LONG] = "data length too long";
    MSGS[PINCODE_LEN_ERROR] = "pin code length must be 8";
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
