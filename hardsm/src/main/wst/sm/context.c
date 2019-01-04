#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"
#include "../include/context.h"


static CryptoContext g_crypto_context;
static int init_statistics(CryptoContext *crypto_context);


int init_context() {
    int error_code = YERR_SUCCESS;

    memset(&g_crypto_context, 0, sizeof(g_crypto_context));

    error_code = init_statistics(&g_crypto_context);
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = open_devices(g_crypto_context.device_list, g_crypto_context.device_count);
    if (error_code != YERR_SUCCESS) return error_code;

    return error_code;
}

int finalize_context() {
    int error_code = YERR_SUCCESS;

    error_code = close_devices(g_crypto_context.device_list, g_crypto_context.device_count);

    return error_code;
}

void print_context(char *buf, int buf_len, bool verbose) {
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

void self_check() {
    // check device
    open_devices(g_crypto_context.device_list, g_crypto_context.device_count);
}

static int init_statistics(CryptoContext *crypto_context) {
    int error_code = YERR_SUCCESS;

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
