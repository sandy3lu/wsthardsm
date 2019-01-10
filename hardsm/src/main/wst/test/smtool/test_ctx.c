#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../api/hardsm.h"
#include "smtool.h"


static void test_print_context();
static void test_login_device();
static void test_logout_device();
static void test_device_status();
static void test_device_count();


void test_ctx() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_init(out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    test_device_count();
    test_login_device();
    test_device_status();
    test_logout_device();


    l = api_final(out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

static void test_print_context() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_print_context(true, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("%s", str_value->value);
    response__free_unpacked(response, NULL);
}

static void test_login_device() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_login_device(0, "11111111", out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

static void test_logout_device() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_logout_device(0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

static void test_device_status() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_device_status(0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    DevStatus *device_status = (DevStatus *)response->device_status;
    print_dev_status(device_status);
    response__free_unpacked(response, NULL);
}

static void test_device_count() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_device_count(out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    IntValue *int_value = (IntValue *)response->int_value;
    printf("device count: %d\n", int_value->value);
    response__free_unpacked(response, NULL);
}
