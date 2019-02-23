#ifndef SMTOOL_H
#define SMTOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

typedef int bool;


void test_ctx();
void check_response(Response *response);
void print_dev_status(DevStatus *device_status);
void print_ctx_info(CtxInfo *ctx_info);
void print_keypair(KeyPair *key_pair);
void print_bytes(BytesValue *bytes);
void test_crypto();

void test_init();
void test_final();
void test_print_context();
void test_open_device(int device_index);
void test_close_device(int device_index);
void test_login_device(char *pincode);
void test_logout_device();
void test_device_status();
int test_ctx_info();
void test_protect_key(int flag);


#ifdef __cplusplus
}
#endif

#endif
