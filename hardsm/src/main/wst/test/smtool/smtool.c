#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../api/hardsm.h"
#include "smtool.h"



int main(int argc, char **argv) {
    test_ctx();
    return 0;
}

void check_response(Response *response) {
    if (response->code != 0) print_response_status(response);
}

void print_dev_status(DevStatus *device_status) {
    printf("index: %d\n", device_status->index);
    printf("opened: %d\n", device_status->opened);
    printf("logged_in: %d\n", device_status->logged_in);
    printf("pipes_count: %d\n", device_status->pipes_count);
    printf("free_pipes_count: %d\n", device_status->free_pipes_count);
    printf("secret_key_count: %d\n", device_status->secret_key_count);
    printf("public_key_count: %d\n", device_status->public_key_count);
    printf("private_key_count: %d\n", device_status->private_key_count);
}
