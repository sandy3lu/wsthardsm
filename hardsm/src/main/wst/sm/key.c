#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/key.h"


static SM_KEY_ATTRIBUTE g_key_attr_sm4;
static SM_KEY_ATTRIBUTE g_key_attr_sm2public;
static SM_KEY_ATTRIBUTE g_key_attr_sm2private;
static SM_ECC_PARAMETER g_ecc_param;
static SM_ALGORITHM g_export_algorithm;

static void init_key_attr_sm4();
static void init_ecc_param();
static void init_key_attr_sm2public();
static void init_key_attr_sm2private();
static void init_export_algorithm();


int init_key_context() {
    init_key_attr_sm4();
    init_ecc_param();
    init_key_attr_sm2public();
    init_key_attr_sm2private();
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

int key_import_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key, bool protect,
                      const char *hex_secret_key, PSM_KEY_HANDLE ph_key) {
    if (strlen(hex_secret_key) > SMMA_ALG35_BLOCK_LEN * 2) return KEY_TOO_LONG;

    char secret_key[SMMA_ALG35_BLOCK_LEN] = {0};
    int key_len = 0;
    from_hex(secret_key, &key_len, hex_secret_key);
    assert(key_len <= sizeof(secret_key));

    PSM_ALGORITHM algorithm = NULL;
    if (protect) {
        algorithm = &g_export_algorithm;
    } else {
        h_auth_key = NULL;
    }

    SM_KEY_HANDLE h_key = NULL;
    int error_code = SM_ImportKey(h_pipe, (PSM_BYTE)secret_key, key_len,
                                  h_auth_key, algorithm, &g_key_attr_sm4, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    *ph_key = h_key;

    return YERR_SUCCESS;
}

int key_destroy_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_key) {
    return SM_DestroyKey(h_pipe, h_key);
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
    if (error_code != YERR_SUCCESS) goto fail;
    assert(key_len <= sizeof(export_key));
    to_hex(out, out_len, export_key, key_len);

    error_code = key_destroy_key(h_pipe, h_key);
    if (error_code != YERR_SUCCESS) goto fail;
    h_key = NULL;

    return error_code;

fail:
    if (h_key != NULL) key_destroy_key(h_pipe, h_key);
    return error_code;
}

/* 1. generate key
 * 2. export key
 * 3. destroy key
 */
int key_generate_keypair(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key,
                         char *public_key, int public_key_len,
                         char *private_key, int private_key_len) {
    if (private_key_len <= SMMA_ECC_FP_256_PRIVATE_KEY_LEN * 2) return BUFSIZE_TOO_SMALL;
    if (public_key_len <= SMMA_ECC_FP_256_PUBLIC_KEY_LEN * 2) return BUFSIZE_TOO_SMALL;

    // generate key pair
    SM_KEY_HANDLE h_pubkey = NULL;
    SM_KEY_HANDLE h_prikey = NULL;
    int error_code = SM_GenerateKeyPair(h_pipe, &g_key_attr_sm2public, &h_pubkey, &g_key_attr_sm2private, &h_prikey);
    if (error_code != YERR_SUCCESS) return error_code;

    // export key pair
    char pub_key[SMMA_ECC_FP_256_PUBLIC_KEY_LEN] = {0};
    char pri_key[SMMA_ECC_FP_256_PRIVATE_KEY_LEN] = {0};
    int pub_key_len = 0, pri_key_len = 0;
    error_code = SM_ExportPublicKey(h_pipe, h_pubkey, (PSM_BYTE)pub_key, (PSM_WORD)&pub_key_len);
    if (error_code != YERR_SUCCESS) goto fail;
    assert(pub_key_len <= sizeof(pub_key));

    PSM_ALGORITHM algorithm = &g_export_algorithm;
    error_code = SM_ExportPrivateKey(h_pipe, h_prikey, h_auth_key, algorithm,
                                     (PSM_BYTE)pri_key, (PSM_WORD)&pri_key_len);
    if (error_code != YERR_SUCCESS) goto fail;
    assert(pri_key_len <= sizeof(pri_key));

    // destroy
    SM_DestroyPublicKey(h_pipe, h_pubkey);
    SM_DestroyPrivateKey(h_pipe, h_prikey);

    // to hex
    to_hex(public_key, public_key_len, pub_key, pub_key_len);
    to_hex(private_key, private_key_len, pri_key, pri_key_len);

    return YERR_SUCCESS;

fail:
    if (h_pubkey != NULL) SM_DestroyPublicKey(h_pipe, h_pubkey);
    if (h_prikey != NULL) SM_DestroyPrivateKey(h_pipe, h_prikey);
    return error_code;
}



static void init_key_attr_sm4() {
    memset(&g_key_attr_sm4,  0, sizeof(SM_KEY_ATTRIBUTE));
    g_key_attr_sm4.uiObjectClass = SMO_SECRET_KEY;
    g_key_attr_sm4.KeyType = SM_KEY_ALG35;
    g_key_attr_sm4.pParameter = SM_NULL;
    g_key_attr_sm4.uiParameterLen = 0;
    g_key_attr_sm4.uiFlags = SMKA_EXTRACTABLE | SMKA_ENCRYPT | SMKA_DECRYPT;
}

static void init_ecc_param() {
    memset(&g_ecc_param,  0, sizeof(SM_ECC_PARAMETER));
    g_ecc_param.uiModulusBits = SMMA_ECC_FP_256_MODULUS_BITS;
}

static void init_key_attr_sm2public() {
    memset(&g_key_attr_sm2public,  0, sizeof(SM_KEY_ATTRIBUTE));
    g_key_attr_sm2public.uiObjectClass = SMO_PUBLIC_KEY;
    g_key_attr_sm2public.KeyType = SM_KEY_ECC_PUBLIC;
    g_key_attr_sm2public.pParameter = &g_ecc_param;
    g_key_attr_sm2public.uiParameterLen = sizeof(SM_ECC_PARAMETER);
    g_key_attr_sm2public.uiFlags = SMKA_VERIFY | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;
}

static void init_key_attr_sm2private() {
    memset(&g_key_attr_sm2private,  0, sizeof(SM_KEY_ATTRIBUTE));
    g_key_attr_sm2private.uiObjectClass = SMO_PRIVATE_KEY;
    g_key_attr_sm2private.KeyType = SM_KEY_ECC_PRIVATE;
    g_key_attr_sm2private.pParameter = &g_ecc_param;
    g_key_attr_sm2private.uiParameterLen = sizeof(SM_ECC_PARAMETER);
    g_key_attr_sm2private.uiFlags = SMKA_SIGN | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;
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
