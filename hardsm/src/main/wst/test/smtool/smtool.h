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
void test_crypto();


#ifdef __cplusplus
}
#endif

#endif
