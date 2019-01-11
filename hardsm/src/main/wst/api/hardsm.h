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


#ifdef __cplusplus
}
#endif

#endif
