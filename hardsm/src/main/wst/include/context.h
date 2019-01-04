#ifndef CONTEXT_H
#define CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_NUMBER   8
#define MAX_MECHANISM_LEN   32
#define MAX_CODE_LEN        64


typedef struct {
    SM_MECHANISM_INFO mechanism_list[MAX_MECHANISM_LEN];
    int mechanisms_len;
    SM_DEVICE_INFO device_info;
    SM_DEVICE_HANDLE h_device;
    int index;
    int opened;
    int log;
    int codes[MAX_CODE_LEN];
    int codes_len;
} DeviceContext;


typedef struct {
    int device_type;
    char api_version[33];
    int device_count;
    DeviceContext device_list[MAX_DEVICE_NUMBER];
} CryptoContext;


int init_context();

int finalize_context();

void print_context(char *buf, int buf_len, bool verbose);

int print_device_context(DeviceContext *device_context, char *buf);

int print_statistics(CryptoContext *crypto_context, char *buf);

#ifdef __cplusplus
}
#endif

#endif
