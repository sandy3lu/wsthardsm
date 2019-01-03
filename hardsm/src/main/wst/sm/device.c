#include <stdio.h>
#include "../include/sm_api.h"
#include "../include/base64.h"
#include "../include/util.h"
#include "../include/device.h"


int get_device_count(int *device_count) {
    *device_count = 0;
    return SM_GetDeviceNum((PSM_UINT)device_count);
}
