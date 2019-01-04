#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"


static void open_device(DeviceContext *device_context) {
    int error_code = SM_OpenDevice(device_context->index, false, &(device_context->h_device));
    if (error_code != YERR_SUCCESS) {
        device_context->opened = false;
        device_context->codes[(device_context->codes_len)++] = error_code;
    } else {
        device_context->opened = true;
    }
}

static void get_mechanisms(DeviceContext *device_context) {
    if (! device_context->opened) return;

    int mechanism_list[MAX_MECHANISM_LEN] = {0};
    int mechanisms_len = 0;
    int error_code = SM_GetMechanismList(device_context->h_device, (PSM_UINT)mechanism_list, (PSM_WORD)&(mechanisms_len));
    if (error_code != YERR_SUCCESS) {
        device_context->codes[(device_context->codes_len)++] = error_code;
        return;
    }

    device_context->mechanisms_len = mechanisms_len;

    int i;
    for (i = 0; i < mechanisms_len; i++) {
        error_code = SM_GetMechanismInfo(device_context->h_device, mechanism_list[i],
                                         &(device_context->mechanism_list[i]));
        if (error_code != YERR_SUCCESS) {
            device_context->codes[(device_context->codes_len)++] = error_code;
        }
    }
}

static void get_device_info(DeviceContext *device_context) {
    int error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS ) {
        device_context->codes[(device_context->codes_len)++] = error_code;
    }
}

int open_devices(DeviceContext device_list[], int device_count) {
    int i;
    for (i = 0; i < device_count; i++) {
        DeviceContext device_context = device_list[i];
        device_context.index = i;
        open_device(&device_context);
        get_mechanisms(&device_context);
        get_device_info(&device_context);
    }

    return YERR_SUCCESS;
}

int close_devices(DeviceContext device_list[], int device_count) {
    int error_code = YERR_SUCCESS;

    int i;
    for (i = 0; i < device_count; i++) {
        DeviceContext device_context = device_list[i];
        if (device_context.opened && NULL != device_context.h_device) {
            int ret = SM_CloseDevice(device_context.h_device);
            if (ret != YERR_SUCCESS) {
                device_context.codes[(device_context.codes_len)++] = ret;
                error_code = DEVICE_CLOSE_ERROR;
            } else {
                device_context.opened = false;
                device_context.h_device = NULL;
            }
        }
    }

    return error_code;
}
