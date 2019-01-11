#include <stdio.h>
#include <assert.h>
#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"
#include "_hardsm.h"


int api_digest(int device_index, int pipe_index, char *data, int data_len, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[256] = {0};
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
