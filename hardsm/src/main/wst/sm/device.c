#include <stdio.h>
#include "../include/base64.h"
#include "../include/util.h"
#include "../include/sm.h"


Handles g_handles;


static Result open_device(PSM_DEVICE_HANDLE ph_device) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    /* 1. get device count */
    int device_count = 0;
    ret = SM_GetDeviceNum((PSM_UINT)&device_count);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }
    if (device_count <= 0) {
        result.code = NO_DEVICE_ERROR;
        strncpy(result.msg, "no sm cipher device found\n", sizeof(result.msg));
        return result;
    }

    /* 2. OpenDevice    */
    ret = SM_OpenDevice(device_count - 1, false, ph_device);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    /* 3. self inspection */
    int inspection_result = 0;
    ret = SM_TestDevice(*ph_device, (PSM_UINT)&inspection_result);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        goto fail;
    }
    if (0 != inspection_result) {
        ret = 400 + inspection_result;
        result.code = ret;
        goto fail;
    }

    return result;


fail:
    SM_CloseDevice(*ph_device);
    return result;
}


static Result close_device(SM_DEVICE_HANDLE h_device) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    if ( h_device != SM_NULL ) {
        ret = SM_CloseDevice(h_device);
    }
    result.code = ret;

    return result;
}


static Result get_device_info(SM_DEVICE_HANDLE h_device, 
                              DeviceInfo *device_info) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    /* get device count */
    ret = SM_GetDeviceNum((PSM_UINT)&(device_info->device_count));
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    /* get device type */
    ret = SM_GetDeviceType((PSM_UINT)&(device_info->device_type));
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    /* get api version */
    char *api_version = SM_GetAPIVersion();
    strncpy(device_info->api_version, api_version, 
            sizeof(device_info->api_version));

    /* get mechanism */
    ret = SM_GetMechanismList(h_device, (PSM_UINT)device_info->mechanism_list, 
                              (PSM_WORD)&(device_info->mechanism_len));
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    /* get sm device info */
    ret = SM_GetDeviceInfo(h_device, &(device_info->sm_device_info));
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    return result;
}


static Result open_security_pipe(SM_DEVICE_HANDLE h_device, 
                                 PSM_PIPE_HANDLE ph_pipe) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;
    ret = SM_OpenSecPipe(h_device, ph_pipe);
    result.code = ret;
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    return result;
}


static Result close_security_pip(SM_PIPE_HANDLE h_pipe) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    if ( h_pipe != SM_NULL ) {
        ret = SM_CloseSecPipe(h_pipe);
    }
    result.code = ret;
    return result;
}


static Result login(SM_PIPE_HANDLE h_pipe, const char *pin_code, 
                    int *try_count, PSM_KEY_HANDLE ph_auth_Key) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    /* login */
    int ret = SM_ERR_FREE;
    ret = SM_Login(h_pipe, (PSM_BYTE)pin_code, 8, (PSM_WORD)try_count);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }

    /* get public key from auth ukey */
    int cfg_key = SMCK_SYMM;    // TODO: why this
    SM_BLOB_KEY   sb_key;
    memset(&sb_key, 0, sizeof(SM_BLOB_KEY));
    sb_key.pbyData = (SM_BYTE*)&cfg_key;
    sb_key.uiDataLen = sizeof(SM_UINT);

    ret = SM_GetCfgKeyHandle(h_pipe, &sb_key, ph_auth_Key);
    if (SM_ERR_FREE != ret) {
        result.code = ret;
        goto fail;
    }

    return result;


fail:
    SM_Logout(h_pipe);
    return result;
}


static Result logout(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_Key) {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    if (NULL != h_auth_Key) {
        ret = SM_CloseTokKeyHdl(h_pipe, h_auth_Key);
    }

    if ( h_pipe != SM_NULL ) {
        ret = SM_Logout(h_pipe);
    }

    result.code = ret;

    return result;
}


/* 1. open device
 * 2. open security pipe
 * 3. get device info
 * 4. login to device
 */
Result device_init(const char *pin_code) {
    /********************/
    MOCK;
    /********************/

    memset(&g_handles, 0, sizeof(g_handles));
    SM_DEVICE_HANDLE h_device   = NULL;
    SM_PIPE_HANDLE   h_pipe     = NULL;
    SM_KEY_HANDLE    h_auth_key = NULL;

    memset(&g_handles, 0, sizeof(Handles));

    Result result = open_device(&h_device);
    if (result.code != SM_ERR_FREE) goto fail;

    result = open_security_pipe(h_device, &h_pipe);
    if (result.code != SM_ERR_FREE) goto fail;

    result = get_device_info(h_device, &(g_handles.device_info));
    if (result.code != SM_ERR_FREE) goto fail;

    int try_count = 0;
    result = login(h_pipe, pin_code, &try_count, &h_auth_key);
    if (result.code != SM_ERR_FREE) goto fail;

    g_handles.h_device = h_device;
    g_handles.h_pipe = h_pipe;
    g_handles.h_auth_key = h_auth_key;

    return result;


fail:
    if (NULL != h_auth_key) logout(h_device, h_auth_key);
    if (NULL != h_pipe) close_security_pip(h_pipe);
    if (NULL != h_device) close_device(h_device);

    return result;
}


/* 1. logout
 * 2. close security pipe
 * 3. close device
 * 4. free redis connect
 * 5. free python interpreter
 */
Result device_finalize() {
    /********************/
    MOCK;
    /********************/

    Result result = init_result();
    Result ret1 = init_result();
    Result ret2 = init_result();
    Result ret3 = init_result();

    if (NULL != g_handles.h_auth_key) {
        ret1 = logout(g_handles.h_pipe, g_handles.h_auth_key);
    }
    if (NULL != g_handles.h_pipe) {
        ret2 = close_security_pip(g_handles.h_pipe);
    }
    if (NULL != g_handles.h_device) {
        ret3 = close_device(g_handles.h_device);
    }
    g_handles.h_device = NULL;
    g_handles.h_pipe = NULL;
    g_handles.h_auth_key = NULL;

    if (ret1.code != SM_ERR_FREE) result = ret1;
    else if (ret2.code != SM_ERR_FREE) result = ret2;
    else if (ret3.code != SM_ERR_FREE) result = ret3;
    else {}

    return result;
}
