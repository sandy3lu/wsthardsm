#include <stdio.h>
#include <assert.h>
#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/util.h"
#include "../include/data.h"


int fail_response(Response *response, int code, uint8_t *out) {
    response->code = code;
    response->has_code = true;
    response->msg = get_error_string(code);

    return response__pack(response, out);
}

int empty_response(Response *response, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    return response__pack(response, out);
}

int bool_response(Response *response, bool value, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    BoolValue bool_value = BOOL_VALUE__INIT;
    bool_value.value = value;
    bool_value.has_value = true;

    response->data_case = RESPONSE__DATA_BOOL_VALUE;
    response->bool_value = &bool_value;

    return response__pack(response, out);
}

int int_response(Response *response, int value, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    IntValue int_value = INT_VALUE__INIT;
    int_value.value = value;
    int_value.has_value = true;

    response->data_case = RESPONSE__DATA_INT_VALUE;
    response->int_value = &int_value;

    return response__pack(response, out);
}

int str_response(Response *response, char *value, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    StrValue str_value = STR_VALUE__INIT;
    str_value.value = value;

    response->data_case = RESPONSE__DATA_STR_VALUE;
    response->str_value = &str_value;

    return response__pack(response, out);
}

int keypair_response(Response *response, char *public_key, char *private_key, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    KeyPair key_pair = KEY_PAIR__INIT;
    key_pair.public_key = public_key;
    key_pair.private_key = private_key;

    response->data_case = RESPONSE__DATA_KEY_PAIR;
    response->key_pair = &key_pair;

    return response__pack(response, out);
}

int device_status_response(Response *response, DeviceStatus *device_status, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    DevStatus dev_status = DEV_STATUS__INIT;

    dev_status.index = device_status->index;
    dev_status.has_index = true;
    dev_status.opened = device_status->opened;
    dev_status.has_opened = true;
    dev_status.logged_in = device_status->logged_in;
    dev_status.has_logged_in = true;
    dev_status.pipes_count = device_status->pipes_count;
    dev_status.has_pipes_count = true;
    dev_status.free_pipes_count = device_status->free_pipes_count;
    dev_status.has_free_pipes_count = true;
    dev_status.secret_key_count = device_status->secret_key_count;
    dev_status.has_secret_key_count = true;
    dev_status.public_key_count = device_status->public_key_count;
    dev_status.has_public_key_count = true;
    dev_status.private_key_count = device_status->private_key_count;
    dev_status.has_private_key_count = true;

    response->data_case = RESPONSE__DATA_DEVICE_STATUS;
    response->device_status = &dev_status;

    return response__pack(response, out);
}

int ctx_info_response(Response *response, ContextInfo *context_info, uint8_t *out) {
    response->code = YERR_SUCCESS;
    response->has_code = true;
    response->msg = "";

    CtxInfo ctx_info = CTX_INFO__INIT;

    ctx_info.protect_key = context_info->protect_key;
    ctx_info.has_protect_key = true;
    ctx_info.device_count = context_info->device_count;
    ctx_info.has_device_count = true;
    ctx_info.api_version = context_info->api_version;

    response->data_case = RESPONSE__DATA_CTX_INFO;
    response->ctx_info = &ctx_info;

    return response__pack(response, out);
}

void print_response_status(Response *response) {
    printf("code: %d\n", response->code);
    printf("msg: %s\n", response->msg);
}
