#ifndef KEY_H
#define KEY_H

#ifdef __cplusplus
extern "C" {
#endif


int key_open_config_key(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_auth_Key);

int key_close_config_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_Key);


#ifdef __cplusplus
}
#endif

#endif
