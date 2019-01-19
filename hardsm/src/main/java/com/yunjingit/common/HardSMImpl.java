package com.yunjingit.common;

import com.yunjingit.common.Sm.KeyPair;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import com.sun.jna.Native;
import com.google.protobuf.InvalidProtocolBufferException;
import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;

/**
 * HardSMImpl is thread safety, but different threads should use there own HardSMImpl instance
 */
public class HardSMImpl implements HardSM {
    private static final int NORMAL_BUF_SIZE = 256;
    private static final int LARGE_BUF_SIZE = 1024 * 32;
    private CSMApi solib;
    private byte[] normal_buf;
    private byte[] large_buf;

    public HardSMImpl() throws SMException {
        File file = null;
        try {
            file = new ResourceUtil().loadLibraryFromJar("/libyjsmwst.so");
            this.solib = Native.load(file.getAbsolutePath(), CSMApi.class);
        } catch (Exception e) {
            throw new FailedLoadLibError(e);
        } finally {
            if (null != file) {
                file.delete();
            }
        }
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

    @Override
    public String apiGenerateKey(int device_index, int pipe_index) throws SMException {
        try {
            int i = this.solib.api_generate_key(device_index, pipe_index, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public KeyPair apiGenerateKeyPair(int device_index, int pipe_index) throws SMException {
        try {
            int i = this.solib.api_generate_keypair(device_index, pipe_index, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getKeyPair();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiEncrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_encrypt(device_index, pipe_index, hex_key, hex_iv,
                data, data.length, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiDecrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_decrypt(device_index, pipe_index, hex_key, hex_iv,
                data, data.length, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiEncryptInit(int device_index, int pipe_index, String hex_key, String hex_iv)
        throws SMException {
        try {
            int i = this.solib.api_encrypt_init(device_index, pipe_index, hex_key, hex_iv, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiEncryptUpdate(int device_index, int pipe_index, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_encrypt_update(device_index, pipe_index, data, data.length, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiEncryptFinal(int device_index, int pipe_index, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_encrypt_final(device_index, pipe_index, data, data.length, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiDecryptInit(int device_index, int pipe_index, String hex_key, String hex_iv)
        throws SMException {
        try {
            int i = this.solib.api_decrypt_init(device_index, pipe_index, hex_key, hex_iv, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiDecryptUpdate(int device_index, int pipe_index, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_decrypt_update(device_index, pipe_index, data, data.length, this.normal_buf);
            byte[] bs = Arrays.copyOfRange(this.normal_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiDecryptFinal(int device_index, int pipe_index, byte[] data)
        throws SMException {
        try {
            int i = this.solib.api_decrypt_final(device_index, pipe_index, data, data.length, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getBytesValue().getValue().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiSign(int device_index, int pipe_index, String hex_key, String hex_data)
        throws SMException {
        try {
            int i = this.solib.api_sign(device_index, pipe_index, hex_key, hex_data, this.large_buf);
            byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public int apiVerify(int device_index, int pipe_index, String hex_key, String hex_data, String hex_signature)
        throws SMException {
            try {
                int i = this.solib.api_verify(device_index, pipe_index, hex_key,
                    hex_data, hex_signature, this.large_buf);
                byte[] bs = Arrays.copyOfRange(this.large_buf, 0, i);
                Sm.Response response = Sm.Response.parseFrom(bs);
                this.parseResponse(response);
                return response.getIntValue().getValue();
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
