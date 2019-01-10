#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/key.h"
#include "../include/crypto.h"


static SM_BYTE g_byiv[SMMA_ALG34_IV_LEN];
static SM_ALGORITHM g_hash_algorithm;
static SM_ALGORITHM g_mac_algorithm;

static void init_mac_algorithm();
static void init_hash_algorithm();
static int is_length_valid(int plain_data_len, int secret_data_len);
static int make_blob_key(SM_BLOB_KEY *blob_key, PSM_KEY_HANDLE ph_key);
static int make_crypt_algorithm(SM_ALGORITHM *algorithm, const char *hex_iv);


int crypto_init_context() {
    init_hash_algorithm();
    init_mac_algorithm();

    return YERR_SUCCESS;
}

int crypto_digest(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len) {
    if (out_len <= SMMA_SCH_256_LEN * 2) return BUFSIZE_TOO_SMALL;

    char digest[SMMA_SCH_256_LEN * 2] = {0};
    int digest_len = sizeof(digest);
    int error_code = SM_Digest(h_pipe, NULL, &g_hash_algorithm, (PSM_BYTE)data,
                               (SM_UINT)data_len, (PSM_BYTE)digest, (PSM_UINT)&digest_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, digest, digest_len);

    return YERR_SUCCESS;
}

int crypto_digest_init(SM_PIPE_HANDLE h_pipe) {
    return SM_DigestInit(h_pipe, NULL, &g_hash_algorithm);
}

int crypto_digest_update(SM_PIPE_HANDLE h_pipe, const char *data, int data_len) {
    return SM_DigestUpdate(h_pipe, (PSM_BYTE)data, (SM_UINT)data_len);
}

int crypto_digest_final(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len) {
    if (out_len <= SMMA_SCH_256_LEN * 2) return BUFSIZE_TOO_SMALL;

    char digest[SMMA_SCH_256_LEN * 2] = {0};
    int digest_len = sizeof(digest);
    int error_code = SM_DigestFinal(h_pipe, (PSM_BYTE)data, (SM_UINT)data_len, (PSM_BYTE)digest, (PSM_UINT)&digest_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, digest, digest_len);

    return YERR_SUCCESS;
}

int crypto_random(SM_PIPE_HANDLE h_pipe, char *out, int out_len) {
    int random_len = (out_len - 1) / 2;
    if (random_len > MAX_RANDOM_LEN) return RANDOM_LEN_OUTOF_BOUND;

    char random[MAX_RANDOM_LEN] = {0};
    int error_code = SM_GenRandom(h_pipe, 0, (PSM_BYTE)random, random_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, random, random_len);

    return YERR_SUCCESS;
}

/* encrypt or decrypt data
 * 1. import key
 * 2. encrypt
 * 3. destroy key */
int crypto_crypt(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                 const char *hex_iv, const char *data, int data_len, char *out, int *out_len) {
    int error_code = is_length_valid(data_len, *out_len);
    if (error_code != YERR_SUCCESS) return error_code;

    SM_BLOB_KEY blob_key;
    SM_ALGORITHM algorithm;
    error_code = make_blob_key(&blob_key, ph_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = make_crypt_algorithm(&algorithm, hex_iv);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_Encrypt(h_pipe, &blob_key, &algorithm, true, (PSM_BYTE)data,
                                data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_Decrypt(h_pipe, &blob_key, &algorithm, true, (PSM_BYTE)data,
                                data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }
    return error_code;
}

int crypto_crypt_init(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                      const char *hex_iv) {
    int error_code = YERR_SUCCESS;

    SM_BLOB_KEY blob_key;
    SM_ALGORITHM algorithm;
    error_code = make_blob_key(&blob_key, ph_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = make_crypt_algorithm(&algorithm, hex_iv);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_EncryptInit(h_pipe, &blob_key, &algorithm);
    } else {
        error_code = SM_DecryptInit(h_pipe, &blob_key, &algorithm);
    }
    return error_code;
}

int crypto_crypt_update(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len) {
    if (data_len != SMMA_ALG35_BLOCK_LEN) return BLOCK_LENGTH_INVALID;
    if (*out_len < data_len) return BUFSIZE_TOO_SMALL;

    int error_code = YERR_SUCCESS;

    if (encrypt) {
        error_code = SM_EncryptUpdate(h_pipe, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_DecryptUpdate(h_pipe, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }

    return error_code;
}

int crypto_crypt_final(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len) {
    int error_code = is_length_valid(data_len, *out_len);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_EncryptFinal(h_pipe, true, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_DecryptFinal(h_pipe, true, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }

    return YERR_SUCCESS;
}


static void init_hash_algorithm() {
    memset(&g_hash_algorithm, 0, sizeof(SM_ALGORITHM));
    g_hash_algorithm.AlgoType = SMM_SCH_256;
    g_hash_algorithm.pParameter = SM_NULL;
    g_hash_algorithm.uiParameterLen = SMMA_SCH_256_LEN;
}

static void init_mac_algorithm() {
    memset(&g_mac_algorithm, 0, sizeof(SM_ALGORITHM));
    g_mac_algorithm.AlgoType = SMM_ALG35_MAC;
    g_mac_algorithm.pParameter = g_byiv;
    g_mac_algorithm.uiParameterLen = SMMA_ALG34_IV_LEN;
}

static int is_length_valid(int plain_data_len, int secret_data_len) {
    int block_len = SMMA_ALG35_BLOCK_LEN;
    int expected_len = (plain_data_len / block_len + 1) * block_len;
    if (secret_data_len < expected_len) return BUFSIZE_TOO_SMALL;
    return YERR_SUCCESS;
}

static int make_blob_key(SM_BLOB_KEY *blob_key, PSM_KEY_HANDLE ph_key) {
    memset(blob_key, 0, sizeof(SM_BLOB_KEY));
    blob_key->pbyData = (SM_BYTE*)ph_key;
    blob_key->uiDataLen = sizeof(SM_KEY_HANDLE);
    return YERR_SUCCESS;
}

static int make_crypt_algorithm(SM_ALGORITHM *algorithm, const char *hex_iv) {
    if (NULL != hex_iv) {
        if (strlen(hex_iv) != SMMA_ALG35_BLOCK_LEN * 2) return IV_LENGTH_INVALID;
    }

    memset(algorithm, 0, sizeof(SM_ALGORITHM));
    if (NULL != hex_iv) {
        char iv[SMMA_ALG35_BLOCK_LEN] = {0};
        int iv_len = sizeof(iv);
        from_hex(iv, &iv_len, hex_iv);
        algorithm->AlgoType = SMM_ALG35_CBC;
        algorithm->pParameter = iv;
        algorithm->uiParameterLen = SMMA_ALG35_IV_LEN;
    } else {
        algorithm->AlgoType = SMM_ALG35_ECB;
        algorithm->pParameter = NULL;
        algorithm->uiParameterLen = 0;
    }

    return YERR_SUCCESS;
}