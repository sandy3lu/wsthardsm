#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/util.h"

static void test_get_localtime() {
    char localtime[33] = {0};
    get_localtime(localtime, sizeof(localtime));
    printf("localtime: %s\n", localtime);
}

static void test_date_today() {
    char today[17] = {0};
    date_today(today, sizeof(today));
    printf("today: %s\n", today);
}

static void test_compress_date() {
    const char *date = "20190101";
    char compressed_date[4] = {0};
    char date1[9] = {0};
    int date1_len = sizeof(date1);

    compress_date(date, compressed_date, &date1_len);
    decompress_date(compressed_date, sizeof(compressed_date),
                    date1, sizeof(date1));
    if (0 != strcmp(date, date1)) {
        printf("compress_date or decompress_date error\n");
    }
}

static void test_is_hex() {
    const char* cases = NULL;
    if (! is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }

    cases = "";
    if (! is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }

    cases = "12345678abcdef";
    if (! is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }

    cases = "12345678ABCDef";
    if (! is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }

    cases = ">2345678abcdef";
    if (is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }

    cases = "2345678abcdef";
    if (is_hex(cases)) {
        printf("is_hex error, case: %s\n", cases);
    }
}

static void _test_to_hex(const char *cases, const char* expect) {
    char hex_result[256] = {0};
    char origin_result[257] = {0};
    int origin_len = 0;
    to_hex(hex_result, sizeof(hex_result), cases, strlen(cases));

    if (0 != strcmp(hex_result, expect)) {
        printf("to_hex or from_hex error, case: %s\n", cases);
        return;
    }

    int error = from_hex(origin_result, &origin_len, hex_result);
    if (error != YERR_SUCCESS || 0 != strcmp(cases, origin_result)) {
        printf("to_hex or from_hex error, case: %s\n", cases);
    }
}

static void test_to_hex() {
    _test_to_hex("", "");
    _test_to_hex("hello", "68656c6c6f");
    _test_to_hex("HELLO", "48454c4c4f");
    _test_to_hex("abcdefg", "61626364656667");
}

void test_util() {
    test_get_localtime();
    test_date_today();
    test_compress_date();
    test_is_hex();
    test_to_hex();
}
