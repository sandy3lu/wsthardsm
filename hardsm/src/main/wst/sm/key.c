#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"
#include "../include/key.h"


static SM_KEY_ATTRIBUTE g_key_attr_sm4;
static SM_ALGORITHM g_export_algorithm;

static void init_key_attr_sm4();
static void init_export_algorithm();


int init_key_context() {
    init_key_attr_sm4();
    init_export_algorithm();
    return YERR_SUCCESS;
}

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

/* 1. generate key
 * 2. export key
 * 3. destroy key
 */
int key_generate_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key, bool protect, char *out, int out_len) {
    if (out_len <= SMMA_ALG35_BLOCK_LEN * 2) return BUFSIZE_TOO_SMALL;

    SM_KEY_HANDLE h_key = NULL;
    int error_code = SM_GenerateKey(h_pipe, &g_key_attr_sm4, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;

    char export_key[SMMA_ALG35_BLOCK_LEN] = {0};
    int key_len = sizeof(export_key);

    PSM_ALGORITHM algorithm = NULL;
    if (protect) {
        algorithm = &g_export_algorithm;
    } else {
        h_auth_key = NULL;
    }

    error_code = SM_ExportKey(h_pipe, h_key, h_auth_key, algorithm, (PSM_BYTE)export_key, (PSM_WORD)&key_len);
    if (error_code != YERR_SUCCESS) return error_code;
    assert(key_len <= sizeof(export_key));
    to_hex(out, out_len, export_key, key_len);

    error_code = SM_DestroyKey(h_pipe, h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    h_key = NULL;

    return YERR_SUCCESS;
}

static void init_key_attr_sm4() {
    memset(&g_key_attr_sm4,  0, sizeof(SM_KEY_ATTRIBUTE));
    g_key_attr_sm4.uiObjectClass = SMO_SECRET_KEY;
    g_key_attr_sm4.KeyType = SM_KEY_ALG35;
    g_key_attr_sm4.pParameter = SM_NULL;
    g_key_attr_sm4.uiParameterLen = 0;
    g_key_attr_sm4.uiFlags = SMKA_EXTRACTABLE | SMKA_ENCRYPT | SMKA_DECRYPT;
}

/* Crypto card can exports all keys (except public key) in ciphertext form. You can choose encrypt exported keys
 * with sm4 (ECB or CBC) or sm3 or sm2.
 * Here we choose sm4 ECB to encrypt it, the simplest way, so pParameter is NULL. */
static void init_export_algorithm() {
    memset(&g_export_algorithm, 0, sizeof(SM_ALGORITHM));
    /* For unknown reason, it's only support ALG34. If use ALG35 then raise KEY TYPE ERROR!
     * But I prefer ALG35.
     * Why use ECB mode? First, keys are short, no need to use CBC or other mode; Second, no iv needed; Third, simple */
    g_export_algorithm.AlgoType = SMM_ALG34_ECB;
    g_export_algorithm.pParameter = NULL;
    g_export_algorithm.uiParameterLen = 0;
}
