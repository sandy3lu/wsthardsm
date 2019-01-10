#ifndef _HARDSM_H
#define _HARDSM_H

#ifdef __cplusplus
extern "C" {
#endif


int fail_response(Response *response, int code, uint8_t *out);
int empty_response(Response *response, uint8_t *out);
int bool_response(Response *response, bool value, uint8_t *out);
int int_response(Response *response, int value, uint8_t *out);
int str_response(Response *response, char *value, uint8_t *out);
int keypair_response(Response *response, char *public_key, char *private_key, uint8_t *out);
int device_status_response(Response *response, DeviceStatus *device_status, uint8_t *out);


#ifdef __cplusplus
}
#endif

#endif
