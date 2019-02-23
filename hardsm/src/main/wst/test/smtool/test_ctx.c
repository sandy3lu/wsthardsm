#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../api/hardsm.h"
#include "smtool.h"


void test_ctx(char *pincode) {
    test_init();

    test_ctx_info();

    test_login_device(pincode);

    test_device_status(0);
    test_crypto();
    test_device_status(0);

    test_logout_device();

    test_final();
}

void test_init() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_init(out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_final() {
    uint8_t out[1024 * 32]  ={0};
    int l = api_final(out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_print_context() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_print_context(true, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("%s", str_value->value);
    response__free_unpacked(response, NULL);
}

void test_open_device(int device_index) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_open_device(device_index, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_close_device(int device_index) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_close_device(device_index, out);
    Response *response = response__unpack(NULL, l, out);
//    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_login_device(char *pincode) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_login_device(0, pincode, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_logout_device() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_logout_device(0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

void test_device_status(int device_index) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_device_status(device_index, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    DevStatus *device_status = (DevStatus *)response->device_status;
    print_dev_status(device_status);
    response__free_unpacked(response, NULL);
}

int test_ctx_info() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_ctx_info(out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    CtxInfo *ctx_info = (CtxInfo *)response->ctx_info;
    print_ctx_info(ctx_info);
    int device_count = ctx_info->device_count;
    response__free_unpacked(response, NULL);
    return device_count;
}

void test_protect_key(int flag) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_protect_key(flag, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}
