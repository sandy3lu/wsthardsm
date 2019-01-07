#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"
#include "../include/check.h"


static CryptoContext g_crypto_context;


void ctx_print_context(char *buf, int buf_len, bool verbose) {
    int delta = 0;
    char *cursor = buf;

    assert(buf_len >= 1024 * 32);

    delta = print_statistics(&g_crypto_context, cursor);
    cursor += delta;

    if (verbose) {
        int i;
        for (i = 0; i < g_crypto_context.device_count; i++) {
            DeviceContext *device_context = &(g_crypto_context.device_list[i]);
            if (device_context->opened) {
                delta = print_device_context(device_context, cursor);
                cursor += delta;
            }
        }
    }
}

int ctx_open_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_context->index = index;
    int error_code = dev_init_device(device_context);

    return error_code;
}

int ctx_close_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_close_device(device_context);
}

int ctx_close_all_devices() {
    int i;
    for (i = 0; i < g_crypto_context.device_count; i++) {
        int error_code = ctx_close_device(i);
        if (error_code != YERR_SUCCESS) return error_code;
    }

    return YERR_SUCCESS;
}

int ctx_get_device_status(int index, DeviceStatus *device_status) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    memset(device_status, 0, sizeof(DeviceStatus));
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_status->index = index;
    device_status->opened = device_context->opened;
    device_status->check_result = device_context->check_result;

    return YERR_SUCCESS;
}

DeviceStatuses ctx_get_device_statuses() {
    DeviceStatuses device_statuses;
    memset(&device_statuses, 0, sizeof(device_statuses));

    int i;
    for (i = 0; i < g_crypto_context.device_count; i++) {
        ctx_get_device_status(i, &device_statuses.device_status_list[i]);
    }
    device_statuses.count = g_crypto_context.device_count;

    return device_statuses;
}

int ctx_device_count() {
    return g_crypto_context.device_count;
}

int ctx_check_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_check_device(device_context);
}

int init_statistics() {
    int error_code = YERR_SUCCESS;
    CryptoContext *crypto_context = &(g_crypto_context);

    int device_count = 0;
    error_code = SM_GetDeviceNum((PSM_UINT)&device_count);
    if (error_code != YERR_SUCCESS) return error_code;

    int device_type = 0;
    const char *api_version = SM_GetAPIVersion();

    error_code = SM_GetDeviceType((PSM_UINT)&device_type);
    if (error_code != YERR_SUCCESS) return error_code;

    strncpy(crypto_context->api_version, api_version,
            sizeof(crypto_context->api_version));
    crypto_context->device_type = device_type;
    crypto_context->device_count = device_count;

    return error_code;
}
