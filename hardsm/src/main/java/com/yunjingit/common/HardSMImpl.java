package com.yunjingit.common;

import java.util.Arrays;
import com.sun.jna.Native;
import com.google.protobuf.InvalidProtocolBufferException;
import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;

/**
 * HardSMImpl is not thread safety, different thread should use there own HardSMImpl instance
 */
public class HardSMImpl implements HardSM {
    private static final int NORMAL_BUF_SIZE = 256;
    private static final int LARGE_BUF_SIZE = 1024 * 32;
    private CSMApi solib;
    private byte[] normal_buf;
    private byte[] large_buf;

    HardSMImpl() {
        this.solib = (CSMApi) Native.loadLibrary("yjsmwst", CSMApi.class);
        this.normal_buf = new byte[NORMAL_BUF_SIZE];
        this.large_buf = new byte[LARGE_BUF_SIZE];
    }

    public void apiInit() throws SMException {
        try {
            int i = this.solib.api_init(this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public void apiFinal() throws SMException {
        try {
            int i = this.solib.api_final(this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public String apiPrintContext(boolean verbose) throws SMException {
        try {
            int i = this.solib.api_print_context(verbose? 1 : 0, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public CtxInfo apiCtxInfo() throws SMException {
        try {
            int i = this.solib.api_ctx_info(this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getCtxInfo();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public void apiLoginDevice(int deviceIndex, String pinCode) throws SMException {
        try {
            int i = this.solib.api_login_device(deviceIndex, pinCode, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public void apiLogoutDevice(int deviceIndex) throws SMException {
        try {
            int i = this.solib.api_logout_device(deviceIndex, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public DevStatus apiDeviceStatus(int deviceIndex) throws SMException {
        try {
            int i = this.solib.api_device_status(deviceIndex, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getDeviceStatus();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    public void apiProtectKey(boolean flag) throws SMException {
        try {
            int i = this.solib.api_protect_key(flag? 1 : 0, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiDigest(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            int i = this.solib.api_digest(device_index, pipe_index, data, data.length, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiDigestInit(int device_index, int pipe_index) throws SMException {
        try {
            int i = this.solib.api_digest_init(device_index, pipe_index, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiDigestUpdate(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            int i = this.solib.api_digest_update(device_index, pipe_index, data, data.length, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiDigestFinal(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            int i = this.solib.api_digest_final(device_index, pipe_index, data, data.length, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiRandom(int device_index, int pipe_index, int length) throws SMException {
        try {
            int i = this.solib.api_random(device_index, pipe_index, length, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    private void parseResponse(Sm.Response response) throws SMException {
        if (response.getCode() != 0) {
            throw new SMException(response.getCode(), response.getMsg());
        }
    }
}
