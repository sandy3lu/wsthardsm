#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MECHANISM_LEN   32
#define MAX_CODE_LEN        64

typedef struct {
    int opened;
    int index;
    int check_result;
    int codes[MAX_CODE_LEN];
    int codes_len;
    SM_MECHANISM_INFO mechanism_list[MAX_MECHANISM_LEN];
    int mechanisms_len;
    SM_DEVICE_INFO device_info;
    SM_DEVICE_HANDLE h_device;
} DeviceContext;


int dev_init_device(DeviceContext *device_context);

int dev_close_device(DeviceContext *device_context);

void dev_refresh_device_contexts(DeviceContext *device_list, int device_count);

int dev_check_device(DeviceContext *device_context);

#ifdef __cplusplus
}
#endif

#endif
