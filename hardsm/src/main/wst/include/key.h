#ifndef KEY_H
#define KEY_H

#ifdef __cplusplus
extern "C" {
#endif


int init_key_context();

int key_open_config_key(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_auth_Key);

int key_close_config_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_Key);

int key_generate_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key,  bool protect, char *out, int out_len);

int key_generate_keypair(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key,
                         char *public_key, int public_key_len,
                         char *private_key, int private_key_len);

int key_import_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key, bool protect,
                      const char *hex_secret_key, PSM_KEY_HANDLE ph_key);

int key_destroy_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_key);

int key_import_private_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_auth_key,
                           const char *hex_key, PSM_KEY_HANDLE ph_key);

int key_destroy_private_key(SM_PIPE_HANDLE h_pipe, SM_KEY_HANDLE h_key);


#ifdef __cplusplus
}
#endif

#endif
