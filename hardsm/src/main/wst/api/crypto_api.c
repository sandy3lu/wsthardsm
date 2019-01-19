#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/crypto.h"
#include "../include/context.h"
#include "_hardsm.h"


#define BUF_LEN  256
#define LARGE_BUF_LEN  1024 * 64 + 64


int api_digest(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[BUF_LEN] = {0};
    error_code = ctx_digest(device_index, pipe_index, data, data_len, hex_out, sizeof(hex_out));
    if (error_code != YERR_SUCCESS) goto fail;

    return str_response(&response, hex_out, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_digest_init(int device_index, int pipe_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_digest_init(device_index, pipe_index);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_digest_update(int device_index, int pipe_index, const char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_digest_update(device_index, pipe_index, data, data_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_digest_final(int device_index, int pipe_index, const char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[256] = {0};
    error_code = ctx_digest_final(device_index, pipe_index, data, data_len, hex_out, sizeof(hex_out));
    if (error_code != YERR_SUCCESS) goto fail;

    return str_response(&response, hex_out, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_random(int device_index, int pipe_index, int length, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[MAX_RANDOM_LEN * 2 + 1] = {0};
    error_code = ctx_random(device_index, pipe_index, hex_out, length * 2 + 1);
    if (error_code != YERR_SUCCESS) goto fail;

    return str_response(&response, hex_out, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_encrypt(int device_index, int pipe_index, char *hex_key, char *hex_iv, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    // Data length greater than 1M is not allowed here
    if (data_len > LARGE_BUF_LEN - 64) return DATA_TOO_LONG;

    char data_out[LARGE_BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_encrypt(device_index, pipe_index, hex_key, hex_iv, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_decrypt(int device_index, int pipe_index, char *hex_key, char *hex_iv, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    // Data length greater than 1M is not allowed here
    if (data_len > LARGE_BUF_LEN - 64) return DATA_TOO_LONG;

    char data_out[LARGE_BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_decrypt(device_index, pipe_index, hex_key, hex_iv, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_encrypt_init(int device_index, int pipe_index, char *hex_key, char *hex_iv, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_encrypt_init(device_index, pipe_index, hex_key, hex_iv);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_decrypt_init(int device_index, int pipe_index, char *hex_key, char *hex_iv, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_decrypt_init(device_index, pipe_index, hex_key, hex_iv);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_encrypt_update(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char data_out[BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_encrypt_update(device_index, pipe_index, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_decrypt_update(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char data_out[BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_decrypt_update(device_index, pipe_index, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_encrypt_final(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    // Data length greater than 1M is not allowed here
    if (data_len > LARGE_BUF_LEN - 64) return DATA_TOO_LONG;

    char data_out[LARGE_BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_encrypt_final(device_index, pipe_index, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_decrypt_final(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    // Data length greater than 1M is not allowed here
    if (data_len > LARGE_BUF_LEN - 64) return DATA_TOO_LONG;

    char data_out[LARGE_BUF_LEN] = {0};
    int data_out_len = sizeof(data_out);
    error_code = ctx_decrypt_final(device_index, pipe_index, data, data_len, data_out, &data_out_len);
    if (error_code != YERR_SUCCESS) goto fail;

    return bytes_response(&response, data_out, data_out_len, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_sign(int device_index, int pipe_index, char *hex_key, char *hex_data, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[BUF_LEN] = {0};
    error_code = ctx_ecc_sign(device_index, pipe_index, hex_key, hex_data, hex_out, sizeof(hex_out));
    if (error_code != YERR_SUCCESS) goto fail;

    return str_response(&response, hex_out, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_verify(int device_index, int pipe_index, char *hex_key, char *hex_data, char *hex_signature, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    int verify_result = 0;
    error_code = ctx_ecc_verify(device_index, pipe_index, hex_key, &verify_result, hex_data, hex_signature);
    if (error_code != YERR_SUCCESS) goto fail;

    return int_response(&response, verify_result, out);

fail:
    return fail_response(&response, error_code, out);
}
