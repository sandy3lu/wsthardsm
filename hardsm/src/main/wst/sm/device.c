#include <stdio.h>
#include "../include/sm_api.h"
#include "../include/base64.h"
#include "../include/util.h"
#include "../include/device.h"

static CryptoContext g_crypto_context;


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

static void open_device(DeviceContext *device_context) {
    int error_code = SM_OpenDevice(device_context->index, false, &(device_context->h_device));
    if (error_code != YERR_SUCCESS) {
        device_context->activated = false;
        device_context->codes[(device_context->codes_len)++] = error_code;
    } else {
        device_context->activated = true;
    }
}

static void get_mechanisms(DeviceContext *device_context) {
    if (! device_context->activated) return;

    int error_code = SM_GetMechanismList(device_context->h_device, (PSM_UINT)(device_context->mechanism_list),
                                        (PSM_WORD)&(device_context->mechanisms_len));
    if (error_code != YERR_SUCCESS) {
        device_context->codes[(device_context->codes_len)++] = error_code;
    }
}

static void get_device_info(DeviceContext *device_context) {
    int error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS ) {
        device_context->codes[(device_context->codes_len)++] = error_code;
    }
}

static int init_devices(CryptoContext *crypto_context) {
    int device_count = crypto_context->device_count;
    int i;
    for (i = 0; i < device_count; i++) {
        DeviceContext *device_context = &(crypto_context->device_list[i]);
        device_context->index = i;
        open_device(device_context);
        get_mechanisms(device_context);
        get_device_info(device_context);
    }

    return YERR_SUCCESS;
}

int init_context() {
    int error_code = YERR_SUCCESS;

    memset(&g_crypto_context, 0, sizeof(g_crypto_context));

    error_code = init_statistics(&g_crypto_context);
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = init_devices(&g_crypto_context);
    if (error_code != YERR_SUCCESS) return error_code;

    return error_code;
}


void print_context(char *buf, int buf_len, bool verbose) {
    int delta = 0;
    char *cursor = buf;

    delta = snprintf(cursor, buf_len, "api version: %s\n", g_crypto_context.api_version);
    printf("delta: %d\n", delta);
    cursor += delta;
    buf_len -= delta;

    buf_len = 0;

//    delta = snprintf(cursor, buf_len, "device type: %d\n", g_crypto_context.device_type);
//    cursor += delta;
//    buf_len -= delta;
//
//    delta = snprintf(cursor, buf_len, "device count: %d\n", g_crypto_context.device_count);
//    cursor += delta;
//    buf_len -= delta;
//
//    if (verbose) {
//        int i;
//        for (i = 0; i < g_crypto_context.device_count; i++) {
//            DeviceContext *device_context = &(g_crypto_context.device_list[i]);
//            delta = snprintf(cursor, buf_len, "--------------------------------\n");
//            cursor += delta;
//            buf_len -= delta;
//
//            delta = snprintf(cursor, buf_len, "device index: %d\n", device_context->index);
//            cursor += delta;
//            buf_len -= delta;
//
//            delta = snprintf(cursor, buf_len, "activated: %d\n", device_context->activated);
//            cursor += delta;
//            buf_len -= delta;
//
//            delta = snprintf(cursor, buf_len, "activated: %d\n", device_context->activated);
//            cursor += delta;
//            buf_len -= delta;
//        }
//        // @TODO: print verbose messages
//    }
}
