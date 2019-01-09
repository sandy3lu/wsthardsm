#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RANDOM_LEN    1024


int crypto_init_context();

int crypto_digest(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len);

int crypto_digest_init(SM_PIPE_HANDLE h_pipe);

int crypto_digest_update(SM_PIPE_HANDLE h_pipe, const char *data, int data_len);

int crypto_digest_final(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len);

int crypto_random(SM_PIPE_HANDLE h_pipe, char *out, int out_len);

int crypto_crypt(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key, bool encrypt, const char *hex_secret_key,
                 bool protect, const char *hex_iv, const char *data, int data_len, char *out, int *out_len);;

#ifdef __cplusplus
}
#endif

#endif
