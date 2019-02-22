#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../include/util.h"
#include "../../api/hardsm.h"
#include "smtool.h"


static char *hex_secret = "9353b0995d93c0b7f470deec26112172";
static char *origin_data_anylen = "012345670123456701234567012345670123456701234567012345670123456";
static char *origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
static char *encrypt_result_anylen = "eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a2927d2a6bf91f625fa4db48fa19cb8645c8";
static char *encrypt_result = "eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a2921bda5859da7534a80121a1e79b859431";

static void test_digest();
static void test_digest_section();
static void test_random();
static void test_generate_key();
static void test_generate_keypair();
static void test_encrypt();
static void test_decrypt();
static void test_encrypt_init_final();
static void test_decrypt_init_final();
static void test_encrypt_section();
static void test_decrypt_section();
static void test_encrypt_section_modlen();
static void test_decrypt_section_modlen();


void test_crypto() {
    test_digest();
    test_digest_section();
    test_random();
    test_generate_key();
    test_generate_keypair();
    test_encrypt();
    test_decrypt();
    test_encrypt_init_final();
    test_decrypt_init_final();
    test_encrypt_section();
    test_decrypt_section();
    test_encrypt_section_modlen();
    test_decrypt_section_modlen();
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

static void test_random() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_random(0, 0, 16, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("random: %s\n", str_value->value);
    response__free_unpacked(response, NULL);
}

static void test_generate_key() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_generate_key(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("secret key: %s\n", str_value->value);
    response__free_unpacked(response, NULL);
}

static void test_generate_keypair() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_generate_keypair(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    KeyPair *key_pair = (KeyPair *)response->key_pair;
    print_keypair(key_pair);
    response__free_unpacked(response, NULL);
}

static void test_encrypt() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_encrypt(0, 0, hex_secret, NULL, origin_data_anylen, strlen(origin_data_anylen), out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    BytesValue *bytes = (BytesValue *)response->bytes_value;
    print_bytes(bytes);
    response__free_unpacked(response, NULL);
}

static void test_decrypt() {
    uint8_t out[1024 * 32]  ={0};

    char data[1024] = {0};
    int data_len = sizeof(out);
    from_hex(data, &data_len, encrypt_result_anylen);

    int l = api_decrypt(0, 0, hex_secret, NULL, data, data_len, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    BytesValue *bytes = (BytesValue *)response->bytes_value;
    printf("decrypt result: %s\n", bytes->value.data);
    response__free_unpacked(response, NULL);
}

static void test_encrypt_init_final() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_encrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    l = api_encrypt_final(0, 0, origin_data, strlen(origin_data), out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    print_bytes(bytes);
    response__free_unpacked(response, NULL);
}

static void test_decrypt_init_final() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_decrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    char data[1024] = {0};
    int data_len = sizeof(out);
    from_hex(data, &data_len, encrypt_result);

    l = api_decrypt_final(0, 0, data, data_len, out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    printf("decrypt result: %s\n", bytes->value.data);
    response__free_unpacked(response, NULL);
}

static void test_encrypt_section() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_encrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    char *buf = origin_data_anylen;
    while (strlen(buf) > 16) {
        l = api_encrypt_update(0, 0, buf, 16, out);
        response = response__unpack(NULL, l, out);
        check_response(response);

        BytesValue *bytes = (BytesValue *)response->bytes_value;
        print_bytes(bytes);
        response__free_unpacked(response, NULL);
        buf += 16;
    }

    l = api_encrypt_final(0, 0, buf, strlen(buf), out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    print_bytes(bytes);
    response__free_unpacked(response, NULL);
}

static void test_decrypt_section() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_decrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    char data[1024] = {0};
    int data_len = sizeof(out);
    from_hex(data, &data_len, encrypt_result_anylen);

    char *buf = data;
    while ((data + data_len - buf) > 16) {
        l = api_decrypt_update(0, 0, buf, 16, out);
        response = response__unpack(NULL, l, out);
        check_response(response);

        BytesValue *bytes = (BytesValue *)response->bytes_value;
        printf("decrypt result: %s\n", bytes->value.data);
        response__free_unpacked(response, NULL);
        buf += 16;
    }

    l = api_decrypt_final(0, 0, buf, data + data_len - buf, out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    printf("decrypt result: %s\n", bytes->value.data);
    response__free_unpacked(response, NULL);
}

static void test_encrypt_section_modlen() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_encrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    char *buf = origin_data;
    while (strlen(buf) > 16) {
        l = api_encrypt_update(0, 0, buf, 16, out);
        response = response__unpack(NULL, l, out);
        check_response(response);

        BytesValue *bytes = (BytesValue *)response->bytes_value;
        print_bytes(bytes);
        response__free_unpacked(response, NULL);
        buf += 16;
    }

    l = api_encrypt_final(0, 0, buf, strlen(buf), out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    print_bytes(bytes);
    response__free_unpacked(response, NULL);
}

static void test_decrypt_section_modlen() {
    uint8_t out[1024 * 32]  ={0};

    int l = api_decrypt_init(0, 0, hex_secret, NULL, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);

    char data[1024] = {0};
    int data_len = sizeof(out);
    from_hex(data, &data_len, encrypt_result);

    char *buf = data;
    while ((data + data_len - buf) > 16) {
        l = api_decrypt_update(0, 0, buf, 16, out);
        response = response__unpack(NULL, l, out);
        check_response(response);

        BytesValue *bytes = (BytesValue *)response->bytes_value;
        printf("decrypt result: %s\n", bytes->value.data);
        response__free_unpacked(response, NULL);
        buf += 16;
    }

    l = api_decrypt_final(0, 0, buf, data + data_len - buf, out);
    response = response__unpack(NULL, l, out);
    check_response(response);

    BytesValue *bytes = (BytesValue *)response->bytes_value;
    printf("decrypt result: %s\n", bytes->value.data);
    response__free_unpacked(response, NULL);
}
