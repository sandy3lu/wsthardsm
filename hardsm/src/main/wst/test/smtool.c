#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/util.h"
#include "../include/sm.h"
#include "../include/api.h"


static void print_response(Response *response) {
    printf("code: %d\n", response->code);
    printf("msg: %s\n", response->msg);
    printf("details: %s\n", response->details);
}

static void test_init(const char *pincode) {
	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = init_login(pincode, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_finalize() {
	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = finalize(out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_gen_key(char *hex_private, char *hex_public) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = gen_key("20101010", "20201010", out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        KeyPair *key_pair = (KeyPair *)response->key_pair;
        strncpy(hex_private, key_pair->private_key,
                strlen(key_pair->private_key));
        strncpy(hex_public, key_pair->public_key,
                strlen(key_pair->public_key));
        printf("private key: %s\n", hex_private);
        printf("public key: %s\n", hex_public);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_sign_data(const char *data, char *data_signed,
                           const char *hex_private) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = sign_data(data, strlen(data), hex_private, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        StrValue *str_value = (StrValue *)response->str_value;
        strncpy(data_signed, str_value->value,
                strlen(str_value->value));
        printf("signature: %s\n", data_signed);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_verify_data(const char *plain_data, const char *signed_data,
                             const char *hex_public) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = verify_data(plain_data, strlen(plain_data),
                        signed_data, hex_public, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        IntValue *int_value = (IntValue *)response->int_value;
        printf("verify result: %d\n", int_value->value);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_sign_st(const char *b64_signature, char *b64_signature_signed,
                         const char *hex_private) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = sign_st(b64_signature, hex_private, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        StrValue *str_value = (StrValue *)response->str_value;
        strncpy(b64_signature_signed, str_value->value,
                strlen(str_value->value));
        printf("signature: %s\n", b64_signature_signed);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_verify_st(const char *b64_signature) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = verify_st(b64_signature, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        IntValue *int_value = (IntValue *)response->int_value;
        printf("verify result: %d\n", int_value->value);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_sign_ct(const char *b64_cert, char *b64_cert_signed,
                         const char *hex_private) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = sign_ct(b64_cert, hex_private, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        StrValue *str_value = (StrValue *)response->str_value;
        strncpy(b64_cert_signed, str_value->value,
                strlen(str_value->value));
        printf("cert: %s\n", b64_cert_signed);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void test_verify_ct(const char *b64_cert) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = verify_ct(b64_cert, out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        IntValue *int_value = (IntValue *)response->int_value;
        printf("verify result: %d\n", int_value->value);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

static void print_cert(const char *b64_cert) {
    MinimalCert cert_out;
    memset(&cert_out, 0, sizeof(MinimalCert));
    Result result = load_cert(b64_cert, &cert_out);
    result = handle_result(result);
    if (result.code != YERR_SUCCESS) {
        fprintf(stderr, "failed load cert: \n");
        fprintf(stderr, "code: %d\n", result.code);
        fprintf(stderr, "msg: %s: \n", result.msg);
        return;
    }

    fprintf(stderr, "cert: %s\n", b64_cert);
    fprintf(stderr, "vs: %s\n", cert_out.vs);
    fprintf(stderr, "pk: %s\n", cert_out.pk);
    fprintf(stderr, "pd: %s\n", cert_out.pd);
    fprintf(stderr, "sg: %s\n", cert_out.da);
    fprintf(stderr, "sd: %s\n", cert_out.sd);
    fprintf(stderr, "ed: %s\n", cert_out.ed);
    fprintf(stderr, "lv: %s\n", cert_out.lv);
    fprintf(stderr, "ts: %s\n", cert_out.ts);
    fprintf(stderr, "mf: %s\n", cert_out.mf);
    fprintf(stderr, "ag: %s\n", cert_out.ag);
    fprintf(stderr, "bt: %s\n", cert_out.bt);
    fprintf(stderr, "fg: %s\n", cert_out.fg);
    fprintf(stderr, "cn: %s\n", cert_out.cn);
    fprintf(stderr, "iu: %s\n", cert_out.iu);
    fprintf(stderr, "sc: %s\n", cert_out.sc);
    fprintf(stderr, "sn: %s\n", cert_out.sn);
    fprintf(stderr, "st: %s\n", cert_out.st);
    fprintf(stderr, "un: %s\n", cert_out.un);
    fprintf(stderr, "id: %s\n", cert_out.id);
    fprintf(stderr, "sg: %s\n", cert_out.sg);
}

static void test_sm3_hash(const char *data) {
   	uint8_t *out = (uint8_t *)malloc(1024 * 1024);
	int l = sm3_hash(data, strlen(data), out);
	Response *response = response__unpack(NULL, l, out);
	print_response(response);
    if (response->code == 0) {
        StrValue *str_value = (StrValue *)response->str_value;
        printf("sm3 digest: %s\n", str_value->value);
    }
	response__free_unpacked(response, NULL);
	free(out);
}

int main(int argc, char **argv) {
    printf("====== test init\n");
    test_init("00000000");

    printf("====== test gen key\n");
    char hex_private[256] = {0};
    char hex_public[256] = {0};
    test_gen_key(hex_private, hex_public);

    printf("====== test sign data\n");
    char data_signed[1024] = {0};
    test_sign_data("hello world", data_signed, hex_private);

    printf("====== test verify data\n");
    test_verify_data("hello world", data_signed, hex_public);

    MinimalCert minimal_cert;
    char b64_cert[MAX_CERT_LEN + 1] = {0};
    memset(&minimal_cert, 0, sizeof(MinimalCert));
    strcpy(minimal_cert.vs, "01");
    strcpy(minimal_cert.pk, hex_public);
    strcpy(minimal_cert.pd, "pd");
    strcpy(minimal_cert.da, "da");
    strcpy(minimal_cert.sg, "sg");
    strcpy(minimal_cert.sd, "20180606");
    strcpy(minimal_cert.ed, "20202010");
    strcpy(minimal_cert.lv, "02");
    strcpy(minimal_cert.ts, "2018:07:07");
    strcpy(minimal_cert.mf, "wst");
    strcpy(minimal_cert.ag, "ag");
    strcpy(minimal_cert.bt, "bt");
    strcpy(minimal_cert.fg, "fg");
    strcpy(minimal_cert.cn, "CN");
    strcpy(minimal_cert.iu, "yunjingit");
    strcpy(minimal_cert.sc, "201806210000000001");
    strcpy(minimal_cert.sn, "yunjing_sample_seal");
    strcpy(minimal_cert.st, "INVOICE");
    strcpy(minimal_cert.un, "use_unit_name");
    strcpy(minimal_cert.id, "201806210000000001");
    Result result = gen_cert(&minimal_cert, b64_cert);
    if (result.code != 0) {
        printf("gen cert failed.\n");
        printf("code: %d, msg: %s\n", result.code, result.msg);
    }

    printf("====== test sign cert\n");
    char b64_cert_signed[MAX_CERT_LEN + 1] = {0};
    test_sign_ct(b64_cert, b64_cert_signed, hex_private);
    print_cert(b64_cert_signed);

    printf("====== test verify cert\n");
    test_verify_ct(b64_cert_signed);

    Signature signature;
    char b64_sig[MAX_SIGNATURE_LEN + 1] = {0};
    memset(&signature, 0, sizeof(signature));
    strcpy(signature.vs, "01");
    strcpy(signature.dh, "1b1b699f0bcf806ee858b82e5298e27c"
                         "138816a2d0acc3d8c376e2546016e942");
    strcpy(signature.ts, "2018:06:02");
    strcpy(signature.mc, "0001-0001-0000-0001");
    strcpy(signature.ct, b64_cert);
    result = gen_signature(&signature, b64_sig);
    if (result.code != 0) {
        printf("gen signature failed.\n");
        printf("code: %d, msg: %s\n", result.code, result.msg);
    }

    printf("====== test sign structure\n");
    memset(data_signed, 0, sizeof(data_signed));
    test_sign_st(b64_sig, data_signed, hex_private);

    printf("====== test verify structure\n");
    test_verify_st(data_signed);

    printf("====== test sm3 hash\n");
    test_sm3_hash("hello");

    printf("====== test finialize\n");
    test_finalize();

    return 0;
}
