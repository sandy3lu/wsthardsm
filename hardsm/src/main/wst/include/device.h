#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_MECHANISM_LEN   32
#define MAX_PIPE_LEN        32
#define MAX_CODE_LEN        64

typedef struct {
    int index;
    int check_result;
    int codes[MAX_CODE_LEN];
    int codes_len;
    int logged_in;
    SM_MECHANISM_INFO mechanism_list[MAX_MECHANISM_LEN];
    int mechanisms_len;
    SM_DEVICE_INFO device_info;
    SM_DEVICE_HANDLE h_device;
    SM_KEY_HANDLE h_auth_key;
    SM_PIPE_HANDLE h_pipes[MAX_PIPE_LEN];
    int pipes_len;
} DeviceContext;


int dev_init_device(DeviceContext *device_context);

int dev_close_device(DeviceContext *device_context);

void dev_refresh_device_contexts(DeviceContext *device_list, int device_count);

int dev_check_device(DeviceContext *device_context);

int dev_status_count(DeviceContext *device_context, int *pipes_count, int *free_pipes_count,
                     int *secret_key_count, int *public_key_count, int *private_key_count);


#ifdef __cplusplus
}
#endif

#endif
