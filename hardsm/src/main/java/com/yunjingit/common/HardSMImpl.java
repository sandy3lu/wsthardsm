package com.yunjingit.common;

import java.io.File;
import java.util.Arrays;
import com.google.protobuf.InvalidProtocolBufferException;
import com.sun.jna.Native;
import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;
import com.yunjingit.common.Sm.KeyPair;

/**
 *HarmSMImpl 并不完全是线程安全的，使用过程中需要注意如下事项:
 * 1. 一个进程应该只实例化一个 HardSMImpl 对象，否者结果是未定义的.
 * 2. 实例化 HardSMImpl 时，应如实传入调用方的最大线程数量，线程数量不应该比加密卡的剩余非对称密钥容量多，否者加密卡将没有足够的资源处理
 * 并发，会报错 NOT ENOUGH RESOURCE.
 * 3. 在调用加密算法时，device_index * 32 + pipe_index 与传入的线程数量是一一对应的，调用方也应该将
 * device_index * 32 + pipe_index 与调用方的线程数量进行对应，否者很可能导致未定义的并发错误.
 */
public class HardSMImpl implements HardSM {
    private static final int NORMAL_BUF_SIZE = 256;
    private static final int LARGE_BUF_SIZE = 1024 * 128 + 128;
    private CSMApi solib;
    private byte[][] normalBuf;
    private byte[][] largeBuf;
    private int threads;

    public HardSMImpl(int threads) throws SMException {
        File file = null;
        try {
            file = new ResourceUtil().loadLibraryFromJar("/libyjsmwst.so");
            this.solib = Native.load(file.getAbsolutePath(), CSMApi.class);
        } catch (Exception e) {
            throw new FailedLoadLibError(e);
        } finally {
            if (null != file) {
                file.deleteOnExit();
                // delete directly may cause core dump, so delete on exit
            }
        }
        this.normalBuf = new byte[threads][];
        this.largeBuf = new byte[threads][];

        for (int i = 0; i < this.normalBuf.length; i++) {
            this.normalBuf[i] = new byte[NORMAL_BUF_SIZE];
        }

        for (int i = 0; i < this.largeBuf.length; i++) {
            this.largeBuf[i] = new byte[LARGE_BUF_SIZE];
        }

        this.threads = threads;
    }

    @Override
    public int getThreads() {
        return this.threads;
    }

    @Override
    public void apiInit() throws SMException {
        try {
            byte[] buf = this.getNormalBuf(0, 0);
            int i = this.solib.api_init(buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiFinal() throws SMException {
        try {
            byte[] buf = this.getNormalBuf(0, 0);
            int i = this.solib.api_final(buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiPrintContext(boolean verbose) throws SMException {
        try {
            byte[] buf = this.getLargeBuf(0, 0);
            int i = this.solib.api_print_context(verbose? 1 : 0, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getStrValue().getValue();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public CtxInfo apiCtxInfo() throws SMException {
        try {
            byte[] buf = this.getNormalBuf(0, 0);
            int i = this.solib.api_ctx_info(buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getCtxInfo();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiLoginDevice(int deviceIndex, String pinCode) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(deviceIndex, 0);
            int i = this.solib.api_login_device(deviceIndex, pinCode, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiLogoutDevice(int deviceIndex) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(deviceIndex, 0);
            int i = this.solib.api_logout_device(deviceIndex, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public DevStatus apiDeviceStatus(int deviceIndex) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(deviceIndex, 0);
            int i = this.solib.api_device_status(deviceIndex, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            return response.getDeviceStatus();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiProtectKey(boolean flag) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(0, 0);
            int i = this.solib.api_protect_key(flag? 1 : 0, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiDigest(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_digest(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_digest_init(device_index, pipe_index, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiDigestUpdate(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_digest_update(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiDigestFinal(int device_index, int pipe_index, byte[] data) throws SMException {
        try {
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_digest_final(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_random(device_index, pipe_index, length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_generate_key(device_index, pipe_index, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_generate_keypair(device_index, pipe_index, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_encrypt(device_index, pipe_index, hex_key, hex_iv, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_decrypt(device_index, pipe_index, hex_key, hex_iv, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_encrypt_init(device_index, pipe_index, hex_key, hex_iv, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_encrypt_update(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_encrypt_final(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            int valueLen = response.getBytesValue().getLen();
            return response.getBytesValue().getValue().substring(0, valueLen).toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public void apiDecryptInit(int device_index, int pipe_index, String hex_key, String hex_iv)
        throws SMException {
        try {
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_decrypt_init(device_index, pipe_index, hex_key, hex_iv, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
            byte[] buf = this.getNormalBuf(device_index, pipe_index);
            int i = this.solib.api_decrypt_update(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            int valueLen = response.getBytesValue().getLen();
            return response.getBytesValue().getValue().substring(0, valueLen).toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public byte[] apiDecryptFinal(int device_index, int pipe_index, byte[] data)
        throws SMException {
        try {
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_decrypt_final(device_index, pipe_index, data, data.length, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
            Sm.Response response = Sm.Response.parseFrom(bs);
            this.parseResponse(response);
            int valueLen = response.getBytesValue().getLen();
            return response.getBytesValue().getValue().substring(0, valueLen).toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new ProtobufError(e);
        }
    }

    @Override
    public String apiSign(int device_index, int pipe_index, String hex_key, String hex_data)
        throws SMException {
        try {
            byte[] buf = this.getLargeBuf(device_index, pipe_index);
            int i = this.solib.api_sign(device_index, pipe_index, hex_key, hex_data, buf);
            byte[] bs = Arrays.copyOfRange(buf, 0, i);
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
                byte[] buf = this.getLargeBuf(device_index, pipe_index);
                int i = this.solib.api_verify(device_index, pipe_index, hex_key, hex_data, hex_signature, buf);
                byte[] bs = Arrays.copyOfRange(buf, 0, i);
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

    private byte[] getNormalBuf(int device_index, int pipe_index) throws SMException {
        return this.getBuf(device_index, pipe_index, this.normalBuf);
    }

    private byte[] getLargeBuf(int device_index, int pipe_index) throws SMException {
        return this.getBuf(device_index, pipe_index, this.largeBuf);
    }

    private byte[] getBuf(int device_index, int pipe_index, byte[][] bufs) throws SMException {
        final int INDEX_OUTOF_BOUND = 603;
        if (device_index < 0 || pipe_index < 0) {
            throw new SMException(INDEX_OUTOF_BOUND, "index out of bound");
        }
        if (pipe_index >= 32) {
            throw new SMException(INDEX_OUTOF_BOUND, "index out of bound");
        }

        int index = device_index * 32 + pipe_index;
        if (index >= this.threads) {
            throw new SMException(INDEX_OUTOF_BOUND, "index out of bound");
        }

        return bufs[index];
    }
}
