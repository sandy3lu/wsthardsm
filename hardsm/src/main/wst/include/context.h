#ifndef CONTEXT_H
#define CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_NUMBER   8


typedef struct {
    int device_type;
    char api_version[33];
    int device_count;
    DeviceContext device_list[MAX_DEVICE_NUMBER];
} CryptoContext;


int init_context();

int finalize_context();

void self_check();

void print_context(char *buf, int buf_len, bool verbose);

int print_device_context(DeviceContext *device_context, char *buf);

int print_statistics(CryptoContext *crypto_context, char *buf);

#ifdef __cplusplus
}
#endif

#endif
