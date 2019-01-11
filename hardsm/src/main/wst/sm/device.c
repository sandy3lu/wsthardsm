#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"


static int check_device_opened(DeviceContext *device_context) {
    if (NULL == device_context->h_device) return DEVICE_NOT_OPENED;
    return YERR_SUCCESS;
}

static int open_device(DeviceContext *device_context) {
    if (YERR_SUCCESS == check_device_opened(device_context)) return YERR_SUCCESS;

    SM_DEVICE_HANDLE h_device = NULL;
    int error_code = SM_OpenDevice(device_context->index, true, &h_device);
    if (error_code == YERR_SUCCESS) {
        device_context->h_device = h_device;
    }
    return error_code;

}

static void get_mechanisms(DeviceContext *device_context) {
    if (YERR_SUCCESS != check_device_opened(device_context)) return;

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
    if (YERR_SUCCESS != check_device_opened(device_context)) return;

    int error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS ) {
        update_error_code(device_context->codes, &(device_context->codes_len), MAX_CODE_LEN, error_code);
    }
}

int dev_init_device(DeviceContext *device_context) {
    if (YERR_SUCCESS != check_device_opened(device_context)) {
        int error_code = open_device(device_context);
        if (error_code != YERR_SUCCESS) return error_code;
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
        SM_DEVICE_HANDLE h_device = device_context->h_device;
        int error_code = SM_CloseDevice(h_device);
        if (error_code != YERR_SUCCESS) {
            return error_code;
        }
        device_context->h_device = NULL;
    }

    return YERR_SUCCESS;
}

int dev_check_device(DeviceContext *device_context) {
    int error_code = check_device_opened(device_context);
    if (YERR_SUCCESS != error_code) return error_code;

    error_code = SM_TestDevice(device_context->h_device, (PSM_UINT)&(device_context->check_result));
    return error_code;
}

int dev_status_count(DeviceContext *device_context, int *pipes_count, int *free_pipes_count,
                     int *secret_key_count, int *public_key_count, int *private_key_count) {
    int error_code = check_device_opened(device_context);
    if (YERR_SUCCESS != error_code) return error_code;

    // refresh device info
    error_code = SM_GetDeviceInfo(device_context->h_device, &(device_context->device_info));
    if (error_code != YERR_SUCCESS) return error_code;

    int max_pipes_count = device_context->device_info.stDevResourceInfo.wMaxPipeCount;
    int _free_pipes_count = device_context->device_info.stDevResourceInfo.wFreePipeCount;
    *pipes_count = max_pipes_count - _free_pipes_count;
    *free_pipes_count = _free_pipes_count;

    int max_secret_key_count = device_context->device_info.stDevResourceInfo.wMaxSecretKeyCount;
    int free_secret_key_count = device_context->device_info.stDevResourceInfo.wFreeSecretKeyCount;
    *secret_key_count = max_secret_key_count - free_secret_key_count;

    int max_public_key_count = device_context->device_info.stDevResourceInfo.wMaxPublicKeyCount;
    int free_public_key_count = device_context->device_info.stDevResourceInfo.wFreePublicKeyCount;
    *public_key_count = max_public_key_count - free_public_key_count;

    int max_private_key_count = device_context->device_info.stDevResourceInfo.wMaxPrivateKeyCount;
    int free_private_key_count = device_context->device_info.stDevResourceInfo.wFreePrivateKeyCount;
    *private_key_count = max_private_key_count - free_private_key_count;

    return YERR_SUCCESS;
}
