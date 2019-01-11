#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../api/hardsm.h"
#include "smtool.h"


static char *origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
static char *encrypt_result = "eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a2921bda5859da7534a80121a1e79b859431";

static void test_digest();
static void test_digest_section();


void test_crypto() {
    test_digest();
    test_digest_section();
}

static void test_digest() {
    uint8_t out[1024 * 32]  ={0};

    char *data = "abc";
    int l = api_digest(0, 0, data, strlen(data), out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("digest: %s\n", str_value->value);
    response__free_unpacked(response, NULL);
}

static void test_digest_section() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_digest_init(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    l = api_digest_update(0, 0, origin_data, strlen(origin_data), out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    l = api_digest_update(0, 0, origin_data, strlen(origin_data), out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    l = api_digest_final(0, 0, origin_data, strlen(origin_data), out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("digest: %s\n", str_value->value);
    response__free_unpacked(response, NULL);
}
