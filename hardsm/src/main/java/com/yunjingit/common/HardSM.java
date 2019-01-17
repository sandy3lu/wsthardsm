package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;
import com.yunjingit.common.Sm.KeyPair;

public interface HardSM {
    void apiInit() throws SMException;

    void apiFinal() throws SMException;

    String apiPrintContext(boolean verbose) throws SMException;

    CtxInfo apiCtxInfo() throws SMException;

    void apiLoginDevice(int deviceIndex, String pinCode) throws SMException;

    void apiLogoutDevice(int deviceIndex) throws SMException;

    DevStatus apiDeviceStatus(int deviceIndex) throws SMException;

    void apiProtectKey(boolean flag) throws SMException;


    String apiDigest(int device_index, int pipe_index, byte[] data) throws SMException;

    void apiDigestInit(int device_index, int pipe_index) throws SMException;

    void apiDigestUpdate(int device_index, int pipe_index, byte[] data) throws SMException;

    String apiDigestFinal(int device_index, int pipe_index, byte[] data) throws SMException;

    String apiRandom(int device_index, int pipe_index, int length) throws SMException;

    String apiGenerateKey(int device_index, int pipe_index) throws SMException;

    KeyPair apiGenerateKeyPair(int device_index, int pipe_index) throws SMException;

    byte[] apiEncrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data) throws SMException;

    byte[] apiDecrypt(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] data) throws SMException;

    void apiEncryptInit(int device_index, int pipe_index, String hex_key, String hex_iv) throws SMException;

    byte[] apiEncryptUpdate(int device_index, int pipe_index, byte[] data) throws SMException;

    byte[] apiEncryptFinal(int device_index, int pipe_index, byte[] data) throws SMException;

    void apiDecryptInit(int device_index, int pipe_index, String hex_key, String hex_iv) throws SMException;

    byte[] apiDecryptUpdate(int device_index, int pipe_index, byte[] data) throws SMException;

    byte[] apiDecryptFinal(int device_index, int pipe_index, byte[] data) throws SMException;

    String apiSign(int device_index, int pipe_index, String hex_key, String hex_data) throws SMException;

    int apiVerify(int device_index, int pipe_index, String hex_key, String hex_data, String hex_signature)
        throws SMException;
}
