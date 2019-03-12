#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RANDOM_LEN    1024


int init_crypto_context();

int crypto_digest(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len);

int crypto_digest_init(SM_PIPE_HANDLE h_pipe);

int crypto_digest_update(SM_PIPE_HANDLE h_pipe, const char *data, int data_len);

int crypto_digest_final(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len);

int crypto_random(SM_PIPE_HANDLE h_pipe, char *out, int out_len);

int crypto_crypt(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                 const char *hex_iv, const char *data, int data_len, char *out, int *out_len);

int crypto_crypt_init(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                      const char *hex_iv);

int crypto_crypt_update(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len);

int crypto_crypt_final(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len);

int crypto_ecc_sign(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key,
                    const char *hex_data, char *hex_out, int hex_out_len);

int crypto_ecc_verify(SM_PIPE_HANDLE h_pipe, const char *hex_key, int *verify_result,
                      const char *hex_data, char *hex_signature);

int crypto_ecc_enc(SM_PIPE_HANDLE h_pipe, const char *hex_key,
                      const char *hex_data,char *hex_out, int hex_out_len);

int crypto_ecc_dec(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key,
                    const char *hex_data, char *hex_out, int hex_out_len);

#ifdef __cplusplus
}
#endif

#endif
