package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;
import com.yunjingit.common.Sm.KeyPair;

public class HardSMMockImpl implements HardSM {

    @Override
    public void apiInit() throws SMException {

    }

    @Override
    public void apiFinal() throws SMException {

    }

    @Override
    public String apiPrintContext(boolean verbose) throws SMException {
        return "";
    }

    @Override
    public CtxInfo apiCtxInfo() throws SMException {
        return CtxInfo.getDefaultInstance();
    }

    @Override
    public void apiLoginDevice(int deviceIndex, String pinCode) throws SMException {

    }

    @Override
    public void apiLoginDevicePipe(int deviceIndex, String pinCode, int pipes) throws SMException{

    }
    @Override
    public void apiLogoutDevice(int deviceIndex) throws SMException {

    }

    @Override
    public DevStatus apiDeviceStatus(int deviceIndex) throws SMException {
        return DevStatus.getDefaultInstance();
    }

    @Override
    public void apiProtectKey(boolean flag) throws SMException {

    }

    @Override
    public String apiDigest(int device_index, int pipe_index, byte[] data) throws SMException {
        return "559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5";
    }

    @Override
    public void apiDigestInit(int device_index, int pipe_index) throws SMException {

    }

    @Override
    public void apiDigestUpdate(int device_index, int pipe_index, byte[] data) throws SMException {

    }

    @Override
    public String apiDigestFinal(int device_index, int pipe_index, byte[] data) throws SMException {
        return "559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5";
    }

    @Override
    public String apiRandom(int device_index, int pipe_index, int length) throws SMException {
        return "559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5";
    }

    @Override
    public String apiGenerateKey(int device_index, int pipe_index) throws SMException {
        return "559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5";
    }

    @Override
    public KeyPair apiGenerateKeyPair(int device_index, int pipe_index) throws SMException {
        com.yunjingit.common.Sm.KeyPair.Builder builder = KeyPair.newBuilder();
        builder.setPrivateKey("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
        builder.setPublicKey("f8b4732c9dac6e007f1615bdb52344050046df7c4d6ea14c4cd9912aea82c593b90bb3a6927b681bdfe3590f0edef1df10350fb03070cd4dcdaec38b1bb2366b");
        return builder.build();
    }

    @Override
    public byte[] apiEncrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data)
        throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public byte[] apiDecrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data)
        throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public void apiEncryptInit(int device_index, int pipe_index, String hex_key, String hex_iv) throws SMException {

    }

    @Override
    public byte[] apiEncryptUpdate(int device_index, int pipe_index, byte[] data) throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public byte[] apiEncryptFinal(int device_index, int pipe_index, byte[] data) throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public void apiDecryptInit(int device_index, int pipe_index, String hex_key, String hex_iv) throws SMException {

    }

    @Override
    public byte[] apiDecryptUpdate(int device_index, int pipe_index, byte[] data) throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public byte[] apiDecryptFinal(int device_index, int pipe_index, byte[] data) throws SMException {
        return DataTransfer.fromHex("559ba1bfa6cdb845388f0fa07cc714376840fc92cf777ee264673fdd8cf99ce5");
    }

    @Override
    public String apiSign(int device_index, int pipe_index, String hex_key, String hex_data) throws SMException {
        return "f8b4732c9dac6e007f1615bdb52344050046df7c4d6ea14c4cd9912aea82c593"
             + "b90bb3a6927b681bdfe3590f0edef1df10350fb03070cd4dcdaec38b1bb2366b";
    }

    @Override
    public int apiVerify(int device_index, int pipe_index, String hex_key, String hex_data, String hex_signature)
        throws SMException {
        return 0;
    }

    @Override
    public String apiSM2Enc(int device_index, int pipe_index, String hex_key, String hex_data) throws SMException {
        return null;
    }

    @Override
    public String apiSM2Dec(int device_index, int pipe_index, String hex_key, String hex_data) throws SMException {
        return null;
    }
}
