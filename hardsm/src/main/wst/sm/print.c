#include <stdio.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"


static int _print_capabilities(int flag, char *buf) {
    int delta = 0;
    char *cursor = buf;

    if (0x00000001 & flag) {
        delta = sprintf(cursor, " encrypt");
        cursor += delta;
    }
    if (0x00000002 & flag) {
        delta = sprintf(cursor, " decrypt");
        cursor += delta;
    }
    if (0x00000004 & flag) {
        delta = sprintf(cursor, " digest");
        cursor += delta;
    }
    if (0x00000008 & flag) {
        delta = sprintf(cursor, " sign(mac)");
        cursor += delta;
    }
    if (0x00000010 & flag) {
        delta = sprintf(cursor, " verify(mac)");
        cursor += delta;
    }
    if (0x00000020 & flag) {
        delta = sprintf(cursor, " wrap");
        cursor += delta;
    }
    if (0x00000040 & flag) {
        delta = sprintf(cursor, " unwrap");
        cursor += delta;
    }

    delta = sprintf(cursor, "\n");
    cursor += delta;

    return cursor - buf;
}


static int _print_mechanism(PSM_MECHANISM_INFO mechanism, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "min block size: %d\n", mechanism->uiMinBlockSize);
    cursor += delta;

    delta = sprintf(cursor, "max block size: %d\n", mechanism->uiMaxBlockSize);
    cursor += delta;

    delta = sprintf(cursor, "min key size: %d\n", mechanism->uiMinKeySize);
    cursor += delta;

    delta = sprintf(cursor, "max key size: %d\n", mechanism->uiMaxKeySize);
    cursor += delta;

    delta = sprintf(cursor, "support algorithms: ");
    cursor += delta;

    delta = _print_capabilities(mechanism->uiFlags, cursor);
    cursor += delta;

    return cursor - buf;
}

static int _print_resource_info(SM_RESOURCE_INFO *resource_info, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "resource info:\n");
    cursor += delta;

    delta = sprintf(cursor, "max pipe count: %d\n", resource_info->wMaxPipeCount);
    cursor += delta;

    delta = sprintf(cursor, "free pipe count: %d\n", resource_info->wFreePipeCount);
    cursor += delta;

    delta = sprintf(cursor, "max secret key count: %d\n", resource_info->wMaxSecretKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "free secret key count: %d\n", resource_info->wFreeSecretKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "max public key count: %d\n", resource_info->wMaxPublicKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "free public key count: %d\n", resource_info->wFreePublicKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "max private key count: %d\n", resource_info->wMaxPrivateKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "free private key count: %d\n", resource_info->wFreePrivateKeyCount);
    cursor += delta;

    delta = sprintf(cursor, "max secret key token count: %d\n", resource_info->wMaxSecretKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "free secret key token count: %d\n", resource_info->wFreeSecretKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "max public key token count: %d\n", resource_info->wMaxPublicKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "free public key token count: %d\n", resource_info->wFreePublicKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "max private key token count: %d\n", resource_info->wMaxPrivateKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "free private key token count: %d\n", resource_info->wFreePrivateKeyTokenCount);
    cursor += delta;

    delta = sprintf(cursor, "max pin len: %d\n", resource_info->wMaxPinLen);
    cursor += delta;

    delta = sprintf(cursor, "min pin len: %d\n", resource_info->wMinPinLen);
    cursor += delta;

    delta = sprintf(cursor, "max so pin len: %d\n", resource_info->wMaxSOPinLen);
    cursor += delta;

    delta = sprintf(cursor, "min so pin len: %d\n", resource_info->wMinSOPinLen);
    cursor += delta;

    delta = sprintf(cursor, "hardware version: %d\n", resource_info->wHardwareVersion);
    cursor += delta;

    delta = sprintf(cursor, "firmware version: %d\n", resource_info->wFirmwareVersion);
    cursor += delta;

    return cursor - buf;
}

static int _print_manufacture_info(SM_MANUFCT_INFO *manufacture_info, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "manufacture info:\n");
    cursor += delta;

    delta = sprintf(cursor, "model: %s\n", manufacture_info->byModel);
    cursor += delta;

    delta = sprintf(cursor, "manufacture id: %s\n", manufacture_info->byManufacturerID);
    cursor += delta;

    delta = sprintf(cursor, "manufacture date: %s\n", manufacture_info->byManufactureDate);
    cursor += delta;

    delta = sprintf(cursor, "batch: %s\n", manufacture_info->byBatch);
    cursor += delta;

    delta = sprintf(cursor, "serial: %s\n", manufacture_info->bySerial);
    cursor += delta;

    delta = sprintf(cursor, "datetime: %s\n", manufacture_info->byDateTime);
    cursor += delta;

    return cursor - buf;
}

static int _print_device_flags(int flag, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "device flags:");
    cursor += delta;

    if (0x00000001 & flag) {
        delta = sprintf(cursor, " F_EXCLUSIVE");
        cursor += delta;
    }
    if (0x00000002 & flag) {
        delta = sprintf(cursor, " F_DEV_LEVEL");
        cursor += delta;
    }
    if (0x00000004 & flag) {
        delta = sprintf(cursor, " F_RNG");
        cursor += delta;
    }
    if (0x00000008 & flag) {
        delta = sprintf(cursor, " F_CLOCK");
        cursor += delta;
    }
    if (0x00000010 & flag) {
        delta = sprintf(cursor, " F_AUTHDEV_REQUIRED");
        cursor += delta;
    }
    if (0x00000020 & flag) {
        delta = sprintf(cursor, " F_LOGIN_REQUIRED");
        cursor += delta;
    }
    if (0x00000040 & flag) {
        delta = sprintf(cursor, " F_USER_PIN_INITIALIZED");
        cursor += delta;
    }
    if (0x00000080 & flag) {
        delta = sprintf(cursor, " F_RESTORE_KEY_NOT_NEEDED");
        cursor += delta;
    }
    if (0x00000100 & flag) {
        delta = sprintf(cursor, " F_RESOURCE_INITIALIZED");
        cursor += delta;
    }
    if (0x00000200 & flag) {
        delta = sprintf(cursor, " F_USER_PIN_COUNT_LOW");
        cursor += delta;
    }
    if (0x00000400 & flag) {
        delta = sprintf(cursor, " F_USER_PIN_LOCKED");
        cursor += delta;
    }
    if (0x00000800 & flag) {
        delta = sprintf(cursor, " F_SO_PIN_COUNT_LOW");
        cursor += delta;
    }
    if (0x00001000 & flag) {
        delta = sprintf(cursor, " F_SO_PIN_LOCKED");
        cursor += delta;
    }

    delta = sprintf(cursor, "\n");
    cursor += delta;

    return cursor - buf;
}

static int _print_device_status(int status, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "device status:");
    cursor += delta;

    if (0x00000000 == status) {
        delta = sprintf(cursor, " F_PY_CHUCHANG");
        cursor += delta;
    }
    if (0x00000001 & status) {
        delta = sprintf(cursor, " F_PY_GONGZUO");
        cursor += delta;
    }
    if (0x00000002 & status) {
        delta = sprintf(cursor, " F_PY_RUKU");
        cursor += delta;
    }

    delta = sprintf(cursor, "\n");
    cursor += delta;

    return cursor - buf;
}

static int _print_device_info(PSM_DEVICE_INFO device_info, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = _print_resource_info(&(device_info->stDevResourceInfo), cursor);
    cursor += delta;

    delta = _print_manufacture_info(&(device_info->stManufactureInfo), cursor);
    cursor += delta;

    delta = _print_device_flags(device_info->uiFlags, cursor);
    cursor += delta;

    delta = _print_device_status(device_info->uiStatus, cursor);
    cursor += delta;

    return cursor - buf;
}

static int _print_testdevice_result(int result, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "device test result: ");
    cursor += delta;

    if (0x00000000 == result) {
        delta = sprintf(cursor, " ok");
        cursor += delta;
    }
    if (0x00000001 & result) {
        delta = sprintf(cursor, " digital physical noise generator error");
        cursor += delta;
    }
    if (0x00000002 & result) {
        delta = sprintf(cursor, " SDRAM error");
        cursor += delta;
    }
    if (0x00000004 & result) {
        delta = sprintf(cursor, " SSX30E error");
        cursor += delta;
    }
    if (0x00000008 & result) {
        delta = sprintf(cursor, " FPGA error");
        cursor += delta;
    }

    delta = sprintf(cursor, "\n");
    cursor += delta;

    return cursor - buf;
}

int print_device_context(DeviceContext *device_context, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "--------------------------------\n");
    cursor += delta;

    delta = sprintf(cursor, "device index: %d\n", device_context->index);
    cursor += delta;

    delta = sprintf(cursor, "opened: %d\n", NULL != device_context->h_device);
    cursor += delta;

    delta = _print_testdevice_result(device_context->check_result, cursor);
    cursor += delta;

    delta = sprintf(cursor, "mechanisms:\n");
    cursor += delta;

    int j;
    for (j = 0; j < device_context->mechanisms_len; j++) {
        delta = _print_mechanism(&(device_context->mechanism_list[j]), cursor);
        cursor += delta;
    }

    delta = sprintf(cursor, "\n");
    cursor += delta;

    delta = sprintf(cursor, "device info:\n");
    cursor += delta;

    delta = _print_device_info(&(device_context->device_info), cursor);
    cursor += delta;

    delta = sprintf(cursor, "errors:\n");
    cursor += delta;

    for (j = 0; j < device_context->codes_len; j++) {
        int code = device_context->codes[j];
        delta = sprintf(cursor, "code %d, msg %s\n", code, get_error_string(code));
        cursor += delta;
    }

    return cursor - buf;
}

int print_statistics(CryptoContext *crypto_context, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "api version: %s\n", crypto_context->api_version);
    cursor += delta;

    delta = sprintf(cursor, "device type: %d\n", crypto_context->device_type);
    cursor += delta;

    delta = sprintf(cursor, "device count: %d\n", crypto_context->device_count);
    cursor += delta;

    return cursor - buf;
}

int print_device_status(DeviceStatus *device_status, char *buf) {
    int delta = 0;
    char *cursor = buf;

    delta = sprintf(cursor, "index: %d\n", device_status->index);
    cursor += delta;

    delta = sprintf(cursor, "opened: %d\n", NULL != device_status->opened);
    cursor += delta;

    delta = sprintf(cursor, "check result: %d\n", device_status->check_result);
    cursor += delta;

    return cursor - buf;
}

int print_device_statuses(DeviceStatuses *device_statuses, char *buf) {
    int delta = 0;
    char *cursor = buf;

    int i;
    for (i = 0; i < device_statuses->count; i++) {
        delta = print_device_status(&(device_statuses->device_status_list[i]), cursor);
        cursor += delta;
    }

    return cursor - buf;
}
