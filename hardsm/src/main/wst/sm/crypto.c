#include <stdio.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/device.h"
#include "../include/crypto.h"


static SM_BYTE g_byiv[SMMA_ALG34_IV_LEN];
static SM_ALGORITHM g_hash_algorithm;
static SM_ALGORITHM g_mac_algorithm;

static void init_mac_algorithm();
static void init_hash_algorithm();


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

static void init_hash_algorithm() {
    memset(&g_hash_algorithm, 0, sizeof(SM_ALGORITHM));
    g_hash_algorithm.AlgoType = SMM_SCH_256;
    g_hash_algorithm.pParameter = SM_NULL;
    g_hash_algorithm.uiParameterLen = SMMA_SCH_256_LEN;
}

static void init_mac_algorithm() {
    memset(&g_mac_algorithm, 0, sizeof(SM_ALGORITHM));
    g_mac_algorithm.AlgoType = SMM_ALG34_MAC;
    g_mac_algorithm.pParameter = g_byiv;
    g_mac_algorithm.uiParameterLen = SMMA_ALG34_IV_LEN;
}
