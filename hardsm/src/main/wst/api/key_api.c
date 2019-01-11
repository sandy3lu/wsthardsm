#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"
#include "_hardsm.h"


int api_generate_key(int device_index, int pipe_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_out[256] = {0};
    error_code = ctx_generate_key(device_index, pipe_index, hex_out, sizeof(hex_out));
    if (error_code != YERR_SUCCESS) goto fail;

    return str_response(&response, hex_out, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_generate_keypair(int device_index, int pipe_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    char hex_private[256] = {0};
    char hex_public[256] = {0};
    error_code = ctx_generate_keypair(device_index, pipe_index, hex_public, sizeof(hex_public),
                                      hex_private, sizeof(hex_private));
    if (error_code != YERR_SUCCESS) goto fail;

    return keypair_response(&response, hex_public, hex_private, out);

fail:
    return fail_response(&response, error_code, out);
}
