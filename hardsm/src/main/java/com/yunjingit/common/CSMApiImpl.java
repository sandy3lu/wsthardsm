package com.yunjingit.common;

import com.sun.jna.Native;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Arrays;

public class CSMApiImpl {
    private static final int NORMAL_BUF_SIZE = 256;
    private static final int LARGE_BUF_SIZE = 1024 * 32;
    private CSMApi solib;
    private byte[] normal_buf;
    private byte[] large_buf;

    CSMApiImpl() {
        this.solib = (CSMApi) Native.loadLibrary("yjsmwst", CSMApi.class);
        this.normal_buf = new byte[NORMAL_BUF_SIZE];
        this.large_buf = new byte[LARGE_BUF_SIZE];
    }

    public void api_init() throws SMException, InvalidProtocolBufferException {
        int i = this.solib.api_init(this.normal_buf);
        byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
        Sm.Response response = Sm.Response.parseFrom(bs);
        this.parseResponse(response);
    }

    public void api_final() throws SMException, InvalidProtocolBufferException {
        int i = this.solib.api_final(this.normal_buf);
        byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
        Sm.Response response = Sm.Response.parseFrom(bs);
        this.parseResponse(response);
    }

    public int api_print_context(int verbose, byte[] out) {
        return 0;
    }

    public int api_login_device(int deviceIndex, String pinCode, byte[] out) {
        return 0;
    }

    private void parseResponse(Sm.Response response) throws SMException {
        if (response.getCode() != 0) {
            throw new SMException(response.getCode(), response.getMsg());
        }
    }
}
