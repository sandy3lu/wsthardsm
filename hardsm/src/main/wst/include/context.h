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


int ctx_open_device(int index);

int ctx_close_device(int index);

int ctx_close_all_devices();

int ctx_get_device_status(int index, DeviceStatus *device_status);

DeviceStatuses ctx_get_device_statuses();

int ctx_check_device(int index);

int init();

int ctx_device_count();

int ctx_open_pipe(int index);

int ctx_close_pipe(int index);

int ctx_close_all_pipe(int index);

int ctx_login(int index, const char *pin_code);

int ctx_logout(int index);

int ctx_digest(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len);

int ctx_digest_init(int device_index, int pipe_index);

int ctx_digest_update(int device_index, int pipe_index, const char *data, int data_len);

int ctx_digest_final(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len);


void ctx_print_context(char *buf, int buf_len, bool verbose);

int print_device_context(DeviceContext *device_context, char *buf);

int print_statistics(CryptoContext *crypto_context, char *buf);

int print_device_status(DeviceStatus *device_status, char *buf);

int print_device_statuses(DeviceStatuses *device_statuses, char *buf);


#ifdef __cplusplus
}
#endif

#endif
