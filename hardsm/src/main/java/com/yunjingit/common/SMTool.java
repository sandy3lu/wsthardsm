package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;

public class SMTool {
    public static void main( String[] args ) throws SMException {
        HardSM hardSM = new HardSMImpl();
        hardSM.apiInit();
        System.out.println(hardSM.apiPrintContext(true));
        SMTool.testCtxInfo(hardSM);

        SMTool.testDevice(hardSM, 0, "11111111");
        SMTool.testDevice(hardSM, 1, "11111111");

        hardSM.apiFinal();
    }

    private static void testCtxInfo(HardSM hardSM) throws SMException {
        CtxInfo ctxInfo = hardSM.apiCtxInfo();
        System.out.println("protect_key: " + ctxInfo.getProtectKey());
        System.out.println("device_count: " + ctxInfo.getDeviceCount());
        System.out.println("api_version: " + ctxInfo.getApiVersion());
    }

    private static void testDevice(HardSM hardSM, int index, String pinCode) throws SMException {
        hardSM.apiLoginDevice(index, pinCode);

        SMTool.testDeviceStatus(hardSM, index);
        SMTool.testDigest(hardSM, index, 0, "abc");
        SMTool.testDigest(hardSM, index, 31, "abc");

        hardSM.apiLogoutDevice(index);
    }

    private static void testDeviceStatus(HardSM hardSM, int index) throws SMException {
        DevStatus devStatus = hardSM.apiDeviceStatus(index);
        System.out.println("index: " + devStatus.getIndex());
        System.out.println("opened: " + devStatus.getOpened());
        System.out.println("logged_in: " + devStatus.getLoggedIn());
        System.out.println("pipes_count: " + devStatus.getFreePipesCount());
        System.out.println("free_pipes_count: " + devStatus.getFreePipesCount());
        System.out.println("secret_key_count: " + devStatus.getSecretKeyCount());
        System.out.println("public_key_count: " + devStatus.getPublicKeyCount());
        System.out.println("private_key_count: " + devStatus.getPrivateKeyCount());
    }

    private static void testDigest(HardSM hardSM, int deviceIndex, int pipeIndex, String data) throws SMException {
        System.out.println(hardSM.apiDigest(deviceIndex, pipeIndex, data.getBytes()));
    }
}
