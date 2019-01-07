#ifndef PIPE_H
#define PIPE_H

#ifdef __cplusplus
extern "C" {
#endif


int pp_open_pipe(DeviceContext *device_context, int free_pipes_count);

int pp_close_pipe(DeviceContext *device_context);

int pp_close_all_pipe(DeviceContext *device_context);

int pp_login(DeviceContext *device_context, const char *pin_code);

int pp_logout(DeviceContext *device_context);


#ifdef __cplusplus
}
#endif

#endif
