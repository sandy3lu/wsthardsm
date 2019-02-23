#include <stdio.h>
#include <assert.h>
#include "../../proto/sm.pb-c.h"
#include "../../include/sm_api.h"
#include "../../include/util.h"
#include "../../api/hardsm.h"
#include "smtool.h"

static void help();
static void build_auth(int index, char *pincode);
static void backup_auth(int index, char *pincode);


int main(int argc, char **argv) {
    if (argc < 2) {
        help();
        return 0;
    }

    char *command = argv[1];
    if (0 == strcmp(command, "help")) {
        help();
        return 0;
    } else if (0 == strcmp(command, "test")) {
        if (argc < 3) {
            help();
            return 0;
        }

        char *pincode = argv[2];
        test_ctx(pincode);
        return 0;
    } else if (0 == strcmp(command, "build")) {
        if (argc < 4) {
            help();
            return 0;
        }

        char *pincode = argv[2];
        int index = atoi(argv[3]);

        test_init();
        test_open_device(index);
        build_auth(index, pincode);
        test_close_device(index);
        test_final();

        return 0;
    } else if (0 == strcmp(command, "backup")) {
        if (argc < 4) {
            help();
            return 0;
        }

        char *pincode = argv[2];
        int index = atoi(argv[3]);

        test_init();
        test_login_device(pincode);
        backup_auth(index, pincode);
        test_logout_device();
        test_final();

        return 0;
    } else {
        help();
        return 0;
    }

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

void print_ctx_info(CtxInfo *ctx_info) {
    printf("protect_key: %d\n", ctx_info->protect_key);
    printf("device_count: %d\n", ctx_info->device_count);
    printf("api_version: %s\n", ctx_info->api_version);
}

void print_keypair(KeyPair *key_pair) {
    printf("public_key: %s\n", key_pair->public_key);
    printf("private_key: %s\n", key_pair->private_key);
}

void print_bytes(BytesValue *bytes) {
    ProtobufCBinaryData *value = &(bytes->value);
    char buf[1024 * 1024 * 4] = {0};
    to_hex(buf, sizeof(buf), (const char *)value->data, value->len);
    printf("data_len: %ld\n", value->len);
    printf("encrypted data: %s\n", buf);
}

static void help() {
    printf("commands:\n");
    printf("help: print this help info\n");
    printf("test <pincode>: execute unit tests\n");
    printf("build <pincode> <index>: choose a card and reset it's ukey\n");
    printf("backup <pincode> <index>: choose a card and backup it's ukey\n");
    printf("2019-2-22 by zhulinfeng\n");
}

static void build_auth(int index, char *pincode) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_build_auth(index, pincode, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}

static void backup_auth(int index, char *pincode) {
    uint8_t out[1024 * 32]  ={0};

    int l = api_backup_auth(index, pincode, out);
    Response *response = response__unpack(NULL, l, out);
    check_response(response);
    response__free_unpacked(response, NULL);
}
