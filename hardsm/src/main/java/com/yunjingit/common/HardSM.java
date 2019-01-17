package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;

public interface HardSM {
    void apiInit() throws SMException;

    void apiFinal() throws SMException;

    String apiPrintContext(boolean verbose) throws SMException;

    CtxInfo apiCtxInfo() throws SMException;

    void apiLoginDevice(int deviceIndex, String pinCode) throws SMException;

    void apiLogoutDevice(int deviceIndex) throws SMException;

    DevStatus apiDeviceStatus(int deviceIndex) throws SMException;

    void apiProtectKey(boolean flag) throws SMException;


    String apiDigest(int device_index, int pipe_index, byte[] data);

    void apiDigestInit(int device_index, int pipe_index);

    void apiDigestUpdate(int device_index, int pipe_index, byte[] data);

    String apiDigestFinal(int device_index, int pipe_index, byte[] data);

    String apiRandom(int device_index, int pipe_index, int length);
}
