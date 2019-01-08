#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"
#include "../include/key.h"


int key_open_config_key(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_auth_Key) {
    int cfg_key = SMCK_SYMM;
    SM_BLOB_KEY   sb_key;
    memset(&sb_key, 0, sizeof(SM_BLOB_KEY));
    sb_key.pbyData = (SM_BYTE*)&cfg_key;
    sb_key.uiDataLen = sizeof(SM_UINT);

    return SM_GetCfgKeyHandle(h_pipe, &sb_key, ph_auth_Key);
}

int key_close_config_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_Key) {
    return SM_CloseTokKeyHdl(h_pipe, h_auth_Key);
}

int key_generate_key(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key) {
    SM_KEY_ATTRIBUTE    stKeyAttr;
    memset(&stKeyAttr,  0, sizeof(SM_KEY_ATTRIBUTE));
    stKeyAttr.uiObjectClass  = SMO_SECRET_KEY;
    stKeyAttr.KeyType        = SM_KEY_ALG34_L;
    stKeyAttr.pParameter     = SM_NULL;
    stKeyAttr.uiParameterLen = 0;
    stKeyAttr.uiFlags        = SMKA_EXTRACTABLE | SMKA_ENCRYPT | SMKA_DECRYPT;

    return SM_GenerateKey(h_pipe, &stKeyAttr, ph_key);
}
