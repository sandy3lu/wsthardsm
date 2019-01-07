#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"


static SM_PIPE_HANDLE get_opened_pipe(DeviceContext *device_context);


int pp_open_pipe(DeviceContext *device_context, int free_pipes_count) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }

    int error_code = YERR_SUCCESS;

    PSM_PIPE_HANDLE pipes = device_context->h_pipes;
    int pipes_len = device_context->pipes_len;

    int i;
    for (i = 0; i < free_pipes_count; i++) {
        if (pipes_len >= MAX_PIPE_LEN) {
            return PIPE_RESOURCE_EXCEEDED;
        }

        SM_PIPE_HANDLE tmp_pipe = NULL;
        error_code = SM_OpenSecPipe(device_context->h_device, &tmp_pipe);
        if (error_code != YERR_SUCCESS) {
            return error_code;
        }
        pipes[pipes_len] = tmp_pipe;
        device_context->pipes_len = ++pipes_len;
    }

    return error_code;
}

int pp_close_pipe(DeviceContext *device_context) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }

    int error_code = YERR_SUCCESS;

    PSM_PIPE_HANDLE pipes = device_context->h_pipes;
    int pipes_len = device_context->pipes_len;

    int i;
    for (i = pipes_len - 1; i >= 0; i--) {
        if (NULL != pipes[i]) {
            error_code = SM_CloseSecPipe(pipes[i]);
            if (error_code != YERR_SUCCESS) {
                return error_code;
            }
        }
        pipes[i] = NULL;
        device_context->pipes_len = i;
    }

    return error_code;
}

int pp_close_all_pipe(DeviceContext *device_context) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }

    int error_code = SM_CloseAllSecPipe(device_context->h_device);
    if (error_code != YERR_SUCCESS) {
        return error_code;
    } else {
        memset(device_context->h_pipes, 0, MAX_PIPE_LEN * sizeof(SM_PIPE_HANDLE));
        device_context->pipes_len = 0;
    }

    return YERR_SUCCESS;
}

int pp_login(DeviceContext *device_context, const char *pin_code) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }
    if (device_context->pipes_len <= 0) {
        return PIPE_NOT_OPENED;
    }

    SM_PIPE_HANDLE pipe = get_opened_pipe(device_context);
    if (NULL == pipe) return PIPE_NOT_OPENED;

    if (device_context->logged_in) return YERR_SUCCESS;

    int pwd_try_count = 0;
    int error_code = SM_Login(pipe, (PSM_UCHAR)pin_code, strlen(pin_code), (PSM_WORD)&pwd_try_count);
    if (error_code == YERR_SUCCESS) {
        device_context->logged_in = true;
    }

    return error_code;
}

int pp_logout(DeviceContext *device_context) {
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }
    if (NULL == device_context->h_pipes) {
        return PIPE_NOT_OPENED;
    }
    SM_PIPE_HANDLE pipe = get_opened_pipe(device_context);
    if (NULL == pipe) return PIPE_NOT_OPENED;
    if (!device_context->logged_in) return YERR_SUCCESS;

    int error_code = SM_Logout(pipe);
    if (error_code == YERR_SUCCESS) {
        device_context->logged_in = false;
    }
    return error_code;
}

static SM_PIPE_HANDLE get_opened_pipe(DeviceContext *device_context) {
    SM_PIPE_HANDLE pipe = NULL;
    int i;
    for (i = 0; i < device_context->pipes_len && pipe == NULL; i++) {
        pipe = device_context->h_pipes[i];
    }
    return pipe;
}