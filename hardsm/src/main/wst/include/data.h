#ifndef DATA_H
#define DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_STATUS_NUMBER   8


typedef struct {
    int index;
    bool opened;
    int check_result;
    int logged_in;
    int pipes_count;
    int free_pipes_count;
    int secret_key_count;
    int public_key_count;
    int private_key_count;
} DeviceStatus;

typedef struct {
    bool protect_key;
    int device_count;
    char api_version[33];
} ContextInfo;


#ifdef __cplusplus
}
#endif

#endif
