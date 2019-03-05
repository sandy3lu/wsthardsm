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


int api_init(uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = init();
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_final(uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = final();
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_print_context(bool verbose, uint8_t *out) {
    Response response = RESPONSE__INIT;

    char buf[32 * 1024] = {0};
    ctx_print_context(buf, sizeof(buf), verbose);

    return str_response(&response, buf, out);
}

int api_open_device(int device_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_open_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_check_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    ctx_free_device(device_index);
    return fail_response(&response, error_code, out);
}


int api_close_device(int device_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_free_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_login_device(int device_index, const char *pin_code, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_open_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_check_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_open_all_pipes(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_login(device_index, pin_code);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    ctx_free_device(device_index);
    return fail_response(&response, error_code, out);
}

// change by lr
int api_login_device_pipe(int device_index, const char *pin_code, uint8_t *out, int pipe) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_open_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_check_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_open_pipes(device_index, pipe);// add a param
    if (error_code != YERR_SUCCESS) goto fail;

    error_code = ctx_login(device_index, pin_code);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    ctx_free_device(device_index);
    return fail_response(&response, error_code, out);
}



int api_logout_device(int device_index, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_free_device(device_index);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_device_status(int device_index, uint8_t *out) {
    Response response = RESPONSE__INIT;

    DeviceStatus device_status = ctx_get_device_status(device_index);
    return device_status_response(&response, &device_status, out);
}

int api_ctx_info(uint8_t *out) {
    Response response = RESPONSE__INIT;

    ContextInfo info = ctx_info();
    return ctx_info_response(&response, &info, out);
}

int api_protect_key(int flag, uint8_t *out) {
    Response response = RESPONSE__INIT;
    ctx_set_protect_key_flag(flag);
    return empty_response(&response, out);
}

int api_build_auth(int device_index, char *pincode, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_build_auth(device_index, pincode);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}

int api_backup_auth(int device_index, char *pincode, uint8_t *out) {
    int error_code = YERR_SUCCESS;
    Response response = RESPONSE__INIT;

    error_code = ctx_backup_auth(device_index, pincode);
    if (error_code != YERR_SUCCESS) goto fail;

    return empty_response(&response, out);

fail:
    return fail_response(&response, error_code, out);
}
