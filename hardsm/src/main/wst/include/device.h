#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

int init_statistics(CryptoContext *crypto_context);

int open_devices(CryptoContext *crypto_context);

int close_devices(CryptoContext *crypto_context);

#ifdef __cplusplus
}
#endif

#endif
