#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"
#include "../include/pipe.h"
#include "../include/key.h"
#include "../include/crypto.h"


static CryptoContext g_crypto_context;
static int init_statistics();
static int check_device_index(int index);
static int check_context_status(int device_index);
static int hash_index(int index, int count);
static int get_pipe_authkey(int device_index, int pipe_index, PSM_PIPE_HANDLE ph_pipe, PSM_KEY_HANDLE ph_auth_key);
static int get_secret_key(int device_index, int pipe_index, SM_KEY_HANDLE *h_key);
static int set_secret_key(int device_index, int pipe_index, SM_KEY_HANDLE h_key);


int init() {
    init_error_string();

    int error_code = init_statistics();
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = init_key_context();
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = YERR_SUCCESS;
    error_code = init_crypto_context();
    if (error_code != YERR_SUCCESS) return error_code;

    return error_code;
}

int final() {
    int error_code = YERR_SUCCESS;

    int i;
    for (i = 0; i < g_crypto_context.device_count; i++) {
        if (NULL != g_crypto_context.device_list[i].h_device) {
            int ret = ctx_free_device(i);
            if (error_code == YERR_SUCCESS) error_code = ret;
        }
    }

    return error_code;
}

void ctx_print_context(char *buf, int buf_len, bool verbose) {
    int delta = 0;
    char *cursor = buf;

    assert(buf_len >= 1024 * 32);

    delta = print_statistics(&g_crypto_context, cursor);
    cursor += delta;

    if (verbose) {
        int i;
        for (i = 0; i < g_crypto_context.device_count; i++) {
            DeviceContext *device_context = &(g_crypto_context.device_list[i]);
            if (NULL != device_context->h_device) {
                delta = print_device_context(device_context, cursor);
                cursor += delta;
            }
        }
    }
}

ContextInfo ctx_info() {
    ContextInfo context_info;
    context_info.protect_key = g_crypto_context.protect_key;
    context_info.device_count = g_crypto_context.device_count;
    memcpy(context_info.api_version, g_crypto_context.api_version, sizeof(context_info.api_version));
    return context_info;
}

int ctx_open_device(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_context->index = index;
    error_code = dev_init_device(device_context);

    return error_code;
}

int ctx_close_device(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_close_device(device_context);
}

DeviceStatus ctx_get_device_status(int index) {
    DeviceStatus device_status;
    memset(&device_status, 0, sizeof(DeviceStatus));

    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return device_status;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_status.index = index;
    device_status.logged_in = device_context->logged_in;
    device_status.opened = NULL != device_context->h_device;
    device_status.check_result = device_context->check_result;

    dev_status_count(device_context, &(device_status.pipes_count), &(device_status.free_pipes_count),
                     &(device_status.secret_key_count), &(device_status.public_key_count),
                     &(device_status.private_key_count));

    return device_status;
}

int ctx_check_device(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_check_device(device_context);
}

int ctx_free_device(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    int ret = ctx_destroy_keys(index);
    if (error_code == YERR_SUCCESS) error_code = ret;
    ret = ctx_logout(index);
    if (error_code == YERR_SUCCESS) error_code = ret;
    ret = ctx_close_all_pipes(index);
    if (error_code == YERR_SUCCESS) error_code = ret;
    ret = ctx_close_device(index);
    if (error_code == YERR_SUCCESS) error_code = ret;

    return error_code;
}

int ctx_open_all_pipes(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    int pipes_count = 0;
    int free_pipes_count = 0;
    int secret_key_count, public_key_count, private_key_count;
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    error_code = dev_status_count(device_context, &pipes_count, &free_pipes_count, &secret_key_count,
                                  &public_key_count, &private_key_count);
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = pp_open_pipe(device_context, free_pipes_count);
    return error_code;
}

int ctx_close_all_pipes(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return pp_close_all_pipe(device_context);
}

int ctx_destroy_keys(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);

    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_key = NULL;
    int i;
    for (i = 0; i < MAX_PIPE_LEN; i++) {
        h_pipe = device_context->h_pipes[i];
        h_key = device_context->h_keys[i];
        if (h_pipe != NULL && h_key != NULL) {
            int ret = key_destroy_key(h_pipe, h_key);
            if (error_code == YERR_SUCCESS) {
                device_context->h_keys[i] = NULL;
                error_code = ret;
            }
        }
    }

    return error_code;
}

int ctx_login(int index, const char *pin_code) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    error_code = pp_login(device_context, pin_code);
    if (error_code != YERR_SUCCESS)  return error_code;


    if (NULL == device_context->h_auth_key) {
        SM_PIPE_HANDLE h_pipe = get_opened_pipe(device_context);
        SM_KEY_HANDLE h_auth_key = NULL;
        error_code = key_open_config_key(h_pipe, &h_auth_key);
        if (error_code != YERR_SUCCESS) return error_code;
        device_context->h_auth_key = h_auth_key;
    }

    return error_code;
}

int ctx_logout(int index) {
    int error_code = check_device_index(index);
    if (error_code != YERR_SUCCESS)  return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);

    if (NULL != device_context->h_auth_key) {
        SM_PIPE_HANDLE h_pipe = get_opened_pipe(device_context);
        SM_KEY_HANDLE h_auth_key = device_context->h_auth_key;
        error_code = key_close_config_key(h_pipe, h_auth_key);
        if (error_code != YERR_SUCCESS) return error_code;
        device_context->h_auth_key = NULL;
    }

    return pp_logout(device_context);
}

void ctx_set_protect_key_flag(bool flag) {
    g_crypto_context.protect_key = flag;
}

bool ctx_get_protect_key_flag() {
    return g_crypto_context.protect_key;
}




int ctx_digest(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_digest(h_pipe, data, data_len, out, out_len);
}

int ctx_digest_init(int device_index, int pipe_index) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_digest_init(h_pipe);
}

int ctx_digest_update(int device_index, int pipe_index, const char *data, int data_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_digest_update(h_pipe, data, data_len);
}

int ctx_digest_final(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_digest_final(h_pipe, data, data_len, out, out_len);
}

int ctx_random(int device_index, int pipe_index, char *out, int out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_random(h_pipe, out, out_len);
}

int ctx_generate_key(int device_index, int pipe_index, char *out, int out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;
    return key_generate_key(h_pipe, h_auth_key, g_crypto_context.protect_key, out, out_len);
}

int ctx_generate_keypair(int device_index, int pipe_index,
                         char *public_key, int public_key_len, char *private_key, int private_key_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return key_generate_keypair(h_pipe, h_auth_key, public_key, public_key_len, private_key, private_key_len);
}

int ctx_encrypt(int device_index, int pipe_index, const char *hex_secret_key,
                const char *hex_iv, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = true;
    SM_KEY_HANDLE h_key = NULL;
    error_code = key_import_key(h_pipe, h_auth_key, g_crypto_context.protect_key, hex_secret_key, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = crypto_crypt(h_pipe, &h_key, encrypt, hex_iv, data, data_len, out, out_len);
    key_destroy_key(h_pipe, h_key);

    return error_code;
}

int ctx_decrypt(int device_index, int pipe_index, const char *hex_secret_key,
                const char *hex_iv, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = false;
    SM_KEY_HANDLE h_key = NULL;
    error_code = key_import_key(h_pipe, h_auth_key, g_crypto_context.protect_key, hex_secret_key, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = crypto_crypt(h_pipe, &h_key, encrypt, hex_iv, data, data_len, out, out_len);
    key_destroy_key(h_pipe, h_key);

    return error_code;
}

int ctx_encrypt_init(int device_index, int pipe_index, const char *hex_secret_key, const char *hex_iv) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    SM_KEY_HANDLE h_key = NULL;
    error_code = get_secret_key(device_index, pipe_index, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    if (NULL != h_key) {
        error_code = key_destroy_key(h_pipe, h_key);
    }
    if (error_code != YERR_SUCCESS) return error_code;
    set_secret_key(device_index, pipe_index, NULL);

    error_code = key_import_key(h_pipe, h_auth_key, g_crypto_context.protect_key, hex_secret_key, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = set_secret_key(device_index, pipe_index, h_key);

    bool encrypt = true;
    return crypto_crypt_init(h_pipe, &h_key, encrypt, hex_iv);
}

int ctx_encrypt_update(int device_index, int pipe_index, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = true;
    return crypto_crypt_update(h_pipe, encrypt, data, data_len, out, out_len);
}

int ctx_encrypt_final(int device_index, int pipe_index, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = true;
    return crypto_crypt_final(h_pipe, encrypt, data, data_len, out, out_len);
}

int ctx_decrypt_init(int device_index, int pipe_index, const char *hex_secret_key, const char *hex_iv) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    SM_KEY_HANDLE h_key = NULL;
    error_code = get_secret_key(device_index, pipe_index, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    if (NULL != h_key) {
        error_code = key_destroy_key(h_pipe, h_key);
    }
    if (error_code != YERR_SUCCESS) return error_code;
    set_secret_key(device_index, pipe_index, NULL);

    error_code = key_import_key(h_pipe, h_auth_key, g_crypto_context.protect_key, hex_secret_key, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = set_secret_key(device_index, pipe_index, h_key);

    bool encrypt = false;
    return crypto_crypt_init(h_pipe, &h_key, encrypt, hex_iv);
}

int ctx_decrypt_update(int device_index, int pipe_index, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = false;
    return crypto_crypt_update(h_pipe, encrypt, data, data_len, out, out_len);
}

int ctx_decrypt_final(int device_index, int pipe_index, const char *data, int data_len, char *out, int *out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    bool encrypt = false;
    return crypto_crypt_final(h_pipe, encrypt, data, data_len, out, out_len);
}

int ctx_ecc_sign(int device_index, int pipe_index, const char *hex_key,
                 const char *hex_data, char *hex_out, int hex_out_len) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    SM_KEY_HANDLE h_key = NULL;
    error_code = key_import_private_key(h_pipe, h_auth_key, hex_key, &h_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = crypto_ecc_sign(h_pipe, &h_key, hex_data, hex_out, hex_out_len);
    key_destroy_private_key(h_pipe, h_key);

    return error_code;
}

int ctx_ecc_verify(int device_index, int pipe_index, const char *hex_key, int *verify_result,
                   const char *hex_data, char *hex_signature) {
    int error_code = YERR_SUCCESS;
    SM_PIPE_HANDLE h_pipe = NULL;
    SM_KEY_HANDLE h_auth_key = NULL;
    error_code = get_pipe_authkey(device_index, pipe_index, &h_pipe, &h_auth_key);
    if (error_code != YERR_SUCCESS) return error_code;

    return crypto_ecc_verify(h_pipe, hex_key, verify_result, hex_data, hex_signature);
}




static int init_statistics() {
    int error_code = YERR_SUCCESS;
    CryptoContext *crypto_context = &(g_crypto_context);

    int device_count = 0;
    error_code = SM_GetDeviceNum((PSM_UINT)&device_count);
    if (error_code != YERR_SUCCESS) return error_code;

    int device_type = 0;
    const char *api_version = SM_GetAPIVersion();

    error_code = SM_GetDeviceType((PSM_UINT)&device_type);
    if (error_code != YERR_SUCCESS) return error_code;

    strncpy(crypto_context->api_version, api_version,
            sizeof(crypto_context->api_version));
    crypto_context->device_type = device_type;
    crypto_context->device_count = device_count;

    return error_code;
}

static int check_device_index(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }
    return YERR_SUCCESS;
}

static int check_context_status(int device_index) {
    int error_code = YERR_SUCCESS;

    error_code = check_device_index(device_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }
    if (device_context->pipes_len <= 0) {
        return PIPE_NOT_OPENED;
    }
    if (!device_context->logged_in) {
        return NEED_LOGIN;
    }

    return error_code;
}

static int hash_index(int index, int count) {
    if (count <= 0) return 0;
    
    index = abs(index);
    index %= count;
    return index;
}

static int get_pipe_authkey(int device_index, int pipe_index, PSM_PIPE_HANDLE ph_pipe, PSM_KEY_HANDLE ph_auth_key) {
    int error_code = YERR_SUCCESS;

    device_index = hash_index(device_index, g_crypto_context.device_count);
    error_code = check_context_status(device_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    pipe_index = hash_index(pipe_index, device_context->pipes_len);

    SM_PIPE_HANDLE h_pipe = device_context->h_pipes[pipe_index];
    *ph_pipe = h_pipe;
    *ph_auth_key = device_context->h_auth_key;

    return error_code;
}

static int get_secret_key(int device_index, int pipe_index, SM_KEY_HANDLE *h_key) {
    int error_code = YERR_SUCCESS;

    device_index = hash_index(device_index, g_crypto_context.device_count);
    error_code = check_context_status(device_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    pipe_index = hash_index(pipe_index, device_context->pipes_len);

    *h_key = device_context->h_keys[pipe_index];

    return error_code;
}

static int set_secret_key(int device_index, int pipe_index, SM_KEY_HANDLE h_key) {
    int error_code = YERR_SUCCESS;

    device_index = hash_index(device_index, g_crypto_context.device_count);
    error_code = check_context_status(device_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    pipe_index = hash_index(pipe_index, device_context->pipes_len);

    device_context->h_keys[pipe_index] = h_key;

    return error_code;
}
