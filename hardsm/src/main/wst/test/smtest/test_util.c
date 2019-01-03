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

void test_util() {
    test_get_localtime();
    test_date_today();
}
