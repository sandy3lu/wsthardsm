#ifndef HARDSM_H
#define HARDSM_H

#ifdef __cplusplus
extern "C" {
#endif


void print_response_status(Response *response);
int api_init(uint8_t *out);
int api_final(uint8_t *out);
int api_print_context(int verbose, uint8_t *out);
int api_ctx_info(uint8_t *out);

/* 1. open device
 * 2. check device
 * 3. open all pipes
 * 4. login */
int api_login_device(int device_index, const char *pin_code, uint8_t *out);

/* free all resources of the device */
int api_logout_device(int device_index, uint8_t *out);

int api_device_status(int device_index, uint8_t *out);

int api_protect_key(int flag, uint8_t *out);

int api_digest(int device_index, int pipe_index, char *data, int data_len, uint8_t *out);

int api_digest_init(int device_index, int pipe_index, uint8_t *out);

int api_digest_update(int device_index, int pipe_index, const char *data, int data_len, uint8_t *out);

int api_digest_final(int device_index, int pipe_index, const char *data, int data_len, uint8_t *out);

int api_random(int device_index, int pipe_index, int length, uint8_t *out);

int api_generate_key(int device_index, int pipe_index, uint8_t *out);

int api_generate_keypair(int device_index, int pipe_index, uint8_t *out);

int api_encrypt(int device_index, int pipe_index, char *hex_key, char *hex_iv, char *data, int data_len, uint8_t *out);

int api_decrypt(int device_index, int pipe_index, char *hex_key, char *hex_iv, char *data, int data_len, uint8_t *out);


#ifdef __cplusplus
}
#endif

#endif
