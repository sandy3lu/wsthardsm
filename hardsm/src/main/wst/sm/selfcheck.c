#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"


void check_devices(DeviceContext *device_list, int device_count) {
    int i;
    for (i = 0; i < device_count; i++) {
        DeviceContext *device_context = &(device_list[i]);
        int error_code = SM_TestDevice(device_context->h_device, (PSM_UINT)&(device_context->check_result));
        update_error_code(device_context->codes, &(device_context->codes_len), MAX_CODE_LEN, error_code);
    }
}
