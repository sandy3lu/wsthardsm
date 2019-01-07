#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"


static int open_device(DeviceContext *device_context) {
    return SM_OpenDevice(device_context->index, false, &(device_context->h_device));

}

static void get_mechanisms(DeviceContext *device_context) {
    if (NULL == device_context->h_device) return;

    int mechanism_list[MAX_MECHANISM_LEN] = {0};
    int mechanisms_len = 0;
    int error_code = SM_GetMechanismList(device_context->h_device, (PSM_UINT)mechanism_list,
                                         (PSM_WORD)&(mechanisms_len));
    if (error_code != YERR_SUCCESS) {
        update_error_code(device_context->codes, &(device_context->codes_len), MAX_CODE_LEN, error_code);
        return;
    }

    device_context->mechanisms_len = mechanisms_len;

    int i;
    for (i = 0; i < mechanisms_len; i++) {
        error_code = SM_GetMechanismInfo(device_context->h_device, mechanism_list[i],
                                         &(device_context->mechanism_list[i]));
        if (error_code != YERR_SUCCESS) {
            update_error_code(device_context->codes, &(device_context->codes_len), MAX_CODE_LEN, error_code);
        }
    }
}

static void get_device_info(DeviceContext *device_context) {
    if (NULL == device_context->h_device) return;

    int error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS ) {
        update_error_code(device_context->codes, &(device_context->codes_len), MAX_CODE_LEN, error_code);
    }
}

int dev_init_device(DeviceContext *device_context) {
    if (NULL == device_context->h_device) {
        int error_code = open_device(device_context);
        if (error_code != YERR_SUCCESS) {
            return error_code;
        }
    }

    get_mechanisms(device_context);
    get_device_info(device_context);

    return YERR_SUCCESS;
}

void dev_refresh_device_contexts(DeviceContext *device_list, int device_count) {
    int i;
    for (i = 0; i < device_count; i++) {
        DeviceContext *device_context = &(device_list[i]);
        get_mechanisms(device_context);
        get_device_info(device_context);
    }
}

int dev_close_device(DeviceContext *device_context) {
    if (NULL != device_context->h_device) {
        int error_code = SM_CloseDevice(device_context->h_device);
        if (error_code != YERR_SUCCESS) {
            return error_code;
        } else {
            device_context->h_device = NULL;
        }
    }

    return YERR_SUCCESS;
}

int dev_check_device(DeviceContext *device_context) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }

    int error_code = SM_TestDevice(device_context->h_device, (PSM_UINT)&(device_context->check_result));
    return error_code;
}

int dev_pipes_count(DeviceContext *device_context, int *max_pipes_count, int *free_pipes_count) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }
    // refresh device info
    int error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS) return error_code;

    *max_pipes_count = device_context->device_info.stDevResourceInfo.wMaxPipeCount;
    *free_pipes_count = device_context->device_info.stDevResourceInfo.wFreePipeCount;
    return YERR_SUCCESS;
}
