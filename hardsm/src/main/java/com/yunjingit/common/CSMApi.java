package com.yunjingit.common;

import com.sun.jna.Library;

public interface CSMApi extends Library {
    int api_init(byte[] out);

    int api_final(byte[] out);

    int api_print_context(int verbose, byte[] out);

    int api_login_device(int deviceIndex, String pinCode, byte[] out);
}

