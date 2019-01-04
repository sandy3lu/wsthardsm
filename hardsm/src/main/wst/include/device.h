#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MECHANISM_LEN   32
#define MAX_CODE_LEN        64

typedef struct {
    int index;
    int opened;
    int check_result;
    int codes[MAX_CODE_LEN];
    int codes_len;
    SM_MECHANISM_INFO mechanism_list[MAX_MECHANISM_LEN];
    int mechanisms_len;
    SM_DEVICE_INFO device_info;
    SM_DEVICE_HANDLE h_device;
} DeviceContext;


int open_devices(DeviceContext *device_list, int device_count);

int close_devices(DeviceContext *device_list, int device_count);

int refresh_device_contexts(DeviceContext *device_list, int device_count);

#ifdef __cplusplus
}
#endif

#endif
