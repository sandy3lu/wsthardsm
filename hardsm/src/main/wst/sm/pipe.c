#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"


int open_pipe(DeviceContext *device_context) {
    return SM_OpenSecPipe(device_context->h_device, &(device_context->h_pipe));
}

int close_pipe(DeviceContext *device_context) {
    if (device_context->h_pipe != NULL) {
        int error_code = SM_CloseSecPipe(device_context->h_pipe);
        if (error_code != YERR_SUCCESS) {
            return error_code;
        } else {
            device_context->h_pipe = NULL;
        }
    }

    return YERR_SUCCESS;
}
