#include <stdio.h>
#include <sys/time.h>
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

static long current_timestamp();
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
static void test_sign_verify();
static void digest_alot();
static void random_alot();
static void encrypt_alot();
static void decrypt_alot();
static void sign_alot();
static void verify_alot();


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
    test_sign_verify();

    digest_alot();
    random_alot();
    encrypt_alot();
    decrypt_alot();
    sign_alot();
    verify_alot();
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

static void test_sign_verify() {
    uint8_t out[1024 * 32] = {0};
    char private_key[256] = {0};
    char public_key[256] = {0};
    char signature[256] = {0};

    // generate key pair
    int l = api_generate_keypair(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    KeyPair *key_pair = (KeyPair *)response->key_pair;
    strncpy(private_key, key_pair->private_key, sizeof(private_key));
    strncpy(public_key, key_pair->public_key, sizeof(public_key));
    response__free_unpacked(response, NULL);

    // sign
    l = api_sign(0, 0, private_key, origin_data, out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    printf("signature: %s\n", str_value->value);
    strncpy(signature, str_value->value, sizeof(signature));
    response__free_unpacked(response, NULL);

    // verify
    l = api_verify(0, 0, public_key, origin_data, signature, out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    IntValue *int_value = (IntValue *)response->int_value;
    printf("verify result: %d\n", int_value->value);
    response__free_unpacked(response, NULL);
}

static void digest_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < counts; i++) {
        char *data = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        int l = api_digest(0, 0, data, strlen(data), out);
        Response *response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("digest performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void random_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < 10000; i++) {
        int l = api_random(0, 0, 16, out);
        Response *response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("random performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void encrypt_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < 10000; i++) {
        int l = api_encrypt(0, 0, hex_secret, NULL, origin_data_anylen, strlen(origin_data_anylen), out);
        Response *response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("encrypt performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void decrypt_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < 10000; i++) {
        char data[1024] = {0};
        int data_len = sizeof(out);
        from_hex(data, &data_len, encrypt_result_anylen);

        int l = api_decrypt(0, 0, hex_secret, NULL, data, data_len, out);
        Response *response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("decrypt performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void sign_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    char private_key[256] = {0};
    char public_key[256] = {0};

    // generate key pair
    int l = api_generate_keypair(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    KeyPair *key_pair = (KeyPair *)response->key_pair;
    strncpy(private_key, key_pair->private_key, sizeof(private_key));
    strncpy(public_key, key_pair->public_key, sizeof(public_key));
    response__free_unpacked(response, NULL);

    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < 10000; i++) {
        l = api_sign(0, 0, private_key, origin_data, out);
        response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("sign performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static void verify_alot() {
    uint8_t out[1024 * 32]  ={0};
    int errors = 0;
    int counts = 10000;

    char private_key[256] = {0};
    char public_key[256] = {0};
    char signature[256] = {0};

    // generate key pair
    int l = api_generate_keypair(0, 0, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    KeyPair *key_pair = (KeyPair *)response->key_pair;
    strncpy(private_key, key_pair->private_key, sizeof(private_key));
    strncpy(public_key, key_pair->public_key, sizeof(public_key));
    response__free_unpacked(response, NULL);

    // sign
    l = api_sign(0, 0, private_key, origin_data, out);
    response = response__unpack(NULL, l, out);
    check_response(response);
    StrValue *str_value = (StrValue *)response->str_value;
    strncpy(signature, str_value->value, sizeof(signature));
    response__free_unpacked(response, NULL);


    long start_timestamp = current_timestamp();

    int i;
    for (i = 0; i < 10000; i++) {
        l = api_verify(0, 0, public_key, origin_data, signature, out);
        response = response__unpack(NULL, l, out);
        if (response->code != 0) errors++;
        response__free_unpacked(response, NULL);
    }

    long stop_timestamp = current_timestamp();

    printf("verify performance test result: \n");
    printf("errors: %d\n", errors);
    printf("counts: %d\n", counts);
    printf("time: %ld\n", stop_timestamp - start_timestamp);
}

static long current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long milliseconds = te.tv_sec * 1000L + te.tv_usec / 1000; // calculate milliseconds
    return milliseconds;
}