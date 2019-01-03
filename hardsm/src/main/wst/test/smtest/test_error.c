#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include "../../include/util.h"


static void test_print_error() {
    int error;
    for (error = 0; error < 5; error++) {
        print_error(error);
    }
    print_error(501);
    print_error(601);
}


void test_error() {
    init_error_string();
    test_print_error();
}
